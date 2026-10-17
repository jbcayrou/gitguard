"""Exec-mode shortcuts when the repository differs from the reference:

1. auto-accept of a pure branch-tracking addition/removal
   (`branch.<x>.remote` / `.merge`, what `push -u`, `branch -u`,
   `checkout -b` write) — no prompt, reference updated;
2. otherwise, diff shown then a question on /dev/tty, default answer N;
   never without a terminal, never when stderr is not a terminal, never with
   GITGUARD_NO_PROMPT, never for "never trusted" nor for a structural
   refusal; the answer is not read from stdin (git would consume it).
"""
from __future__ import annotations

import os
import select
import subprocess
import sys
import time
from pathlib import Path

import pytest

from tests.conftest import GG, GITGUARD

# ------------------------------------------------------------------ auto-accept

def with_origin(gg: GG, repo: Path, subsrc: Path) -> None:
    """Trusted repository with an `origin` remote (remote add requires a trust)."""
    assert gg.git("remote", "add", "origin", str(subsrc), cwd=repo).rc == 0
    gg.trust(repo)
    assert not gg.check(repo).blocked


def test_push_u_accepted_without_prompt(gg: GG, repo: Path, subsrc: Path) -> None:
    """`push -u` writes the config AFTER the check: the next command sees the
    difference and accepts it on its own."""
    with_origin(gg, repo, subsrc)
    assert gg.run("git", "checkout", "-qb", "feat", cwd=repo).rc == 0
    r = gg.run("git", "push", "-qu", "origin", "feat", cwd=repo)
    assert r.rc == 0, r.text
    assert "branch.feat.remote=origin" in gg.git("config", "--list", cwd=repo).out
    r = gg.run("git", "status", cwd=repo)
    assert r.rc == 0 and "On branch" in r.out, r.text
    assert "branch tracking for feat" in r.err and "has changed" not in r.err
    assert not gg.check(repo).blocked, "reference updated"
    assert "branch tracking" not in gg.run("git", "status", cwd=repo).err, "only once"
    # Removing the tracking: accepted too.
    assert gg.run("git", "branch", "--unset-upstream", cwd=repo).rc == 0
    r = gg.run("git", "status", cwd=repo)
    assert r.rc == 0 and "branch tracking for feat" in r.err
    assert not gg.check(repo).blocked


def test_branch_u_from_linked_worktree(gg: GG, repo: Path, subsrc: Path, tmp_path: Path) -> None:
    """From a linked worktree, git writes into the main repository's config
    (scope `common`): same shortcut."""
    with_origin(gg, repo, subsrc)
    wt = tmp_path / "wt"
    assert gg.git("worktree", "add", "-q", str(wt), "-b", "wtb", cwd=repo).rc == 0
    gg.trust(repo)
    gg.trust(wt)                                 # the linked worktree has its own key
    assert gg.git("fetch", "-q", "origin", cwd=repo).rc == 0
    assert gg.run("git", "branch", "-u", "origin/main", cwd=wt).rc == 0
    assert gg.check(wt).blocked, "common:config has changed"
    r = gg.run("git", "status", cwd=wt)
    assert r.rc == 0 and "branch tracking for wtb" in r.err, r.text
    assert not gg.check(wt).blocked
    r = gg.run("git", "status", cwd=repo)        # the main repository sees the same difference
    assert r.rc == 0 and "branch tracking for wtb" in r.err, r.text
    assert not gg.check(repo).blocked


def test_check_mode_still_reports(gg: GG, repo: Path, subsrc: Path) -> None:
    """`gitguard` alone (diagnostic) re-trusts nothing: it reports."""
    with_origin(gg, repo, subsrc)
    gg.git("config", "branch.feat.remote", "origin", cwd=repo)
    gg.git("config", "branch.feat.merge", "refs/heads/feat", cwd=repo)
    assert gg.check(repo).blocked
    assert gg.run("git", "status", cwd=repo).rc == 0     # exec: accepted
    assert not gg.check(repo).blocked


@pytest.mark.parametrize("extra", [
    ("core.fsmonitor", "/tmp/evil"),
    ("branch.feat.rebase", "true"),
    ("remote.evil.url", "/tmp/evil"),
    ("alias.st", "!id"),
])
def test_branch_plus_anything_else_refused(gg: GG, repo: Path, subsrc: Path, extra) -> None:
    with_origin(gg, repo, subsrc)
    gg.git("config", "branch.feat.remote", "origin", cwd=repo)
    gg.git("config", "branch.feat.merge", "refs/heads/feat", cwd=repo)
    gg.git("config", *extra, cwd=repo)
    r = gg.run("git", "status", cwd=repo)
    assert r.blocked and "On branch" not in r.out, r.text
    assert "has changed" in r.err
    assert gg.check(repo).blocked, "not re-trusted"


def test_branch_tracking_to_unknown_remote_refused(gg: GG, repo: Path, subsrc: Path) -> None:
    with_origin(gg, repo, subsrc)
    gg.git("config", "branch.feat.remote", "elsewhere", cwd=repo)
    gg.git("config", "branch.feat.merge", "refs/heads/feat", cwd=repo)
    assert gg.run("git", "status", cwd=repo).blocked


def test_branch_tracking_plus_hook_refused(gg: GG, repo: Path, subsrc: Path) -> None:
    from tests.conftest import write_exec
    with_origin(gg, repo, subsrc)
    gg.git("config", "branch.feat.remote", "origin", cwd=repo)
    gg.git("config", "branch.feat.merge", "refs/heads/feat", cwd=repo)
    write_exec(repo / ".git/hooks/pre-commit")
    assert gg.run("git", "status", cwd=repo).blocked


# ----------------------------------------------------------------------- prompt

def run_with_tty(gg: GG, args: list[str], cwd: Path, answer: str | None,
                 stdin_data: bytes | None = None, env: dict | None = None):
    """Run gitguard with a pseudo-terminal as controlling terminal (so /dev/tty
    can be opened) and stderr on that terminal; stdout captured; stdin = pipe
    if `stdin_data`, else the terminal. Answers `answer` on the terminal when
    the question appears. Returns (rc, stdout, tty output)."""
    import pty
    import fcntl
    import termios
    master, slave = pty.openpty()

    def preexec() -> None:
        os.setsid()
        fcntl.ioctl(slave, termios.TIOCSCTTY, 0)

    p = subprocess.Popen(
        [sys.executable, str(GITGUARD), *args], cwd=cwd, env={**gg.env, **(env or {})},
        stdin=subprocess.PIPE if stdin_data is not None else slave,
        stdout=subprocess.PIPE, stderr=slave, preexec_fn=preexec, close_fds=True)
    os.close(slave)
    tty_out = b""
    deadline = time.monotonic() + 30
    asked = False
    while time.monotonic() < deadline:
        r, _, _ = select.select([master], [], [], 0.2)
        if r:
            try:
                chunk = os.read(master, 4096)
            except OSError:
                break
            if not chunk:
                break
            tty_out += chunk
        if not asked and answer is not None and b"[y/N]" in tty_out:
            os.write(master, answer.encode() + b"\n")
            asked = True
        if p.poll() is not None and not r:
            break
    out, _ = p.communicate(input=stdin_data, timeout=30)
    os.close(master)
    return p.returncode, out.decode(errors="replace"), tty_out.decode(errors="replace")


def modify(gg: GG, repo: Path) -> None:
    gg.git("config", "core.pager", "cat", cwd=repo)    # change that cannot be auto-accepted


@pytest.mark.parametrize("answer, accepted", [("y", True), ("yes", True), ("Y", True),
                                              ("", False), ("n", False), ("no", False)])
def test_prompt_answers(gg: GG, repo: Path, answer: str, accepted: bool) -> None:
    modify(gg, repo)
    rc, out, tty = run_with_tty(gg, ["git", "status"], repo, answer)
    assert "[y/N]" in tty and "pager = cat" in tty, tty      # diff shown before the question
    if accepted:
        assert rc == 0 and "On branch" in out, (rc, out, tty)
        assert not gg.check(repo).blocked, "reference updated"
    else:
        assert rc != 0 and "On branch" not in out, (rc, out, tty)
        assert gg.check(repo).blocked, "reference unchanged"


def test_prompt_trusts_exactly_what_was_shown(gg: GG, repo: Path) -> None:
    """The trusted state is the one of the displayed diff, not a recomputed one."""
    import json
    modify(gg, repo)
    rc, out, tty = run_with_tty(gg, ["git", "status"], repo, "y")
    assert rc == 0
    man = json.loads(gg.key_for(repo).read_text())
    cfg = [e for e in man["entries"] if e["scope"] == "local" and e["path"] == "config"]
    import hashlib
    assert cfg and cfg[0]["sha"] == hashlib.sha256((repo / ".git/config").read_bytes()).hexdigest()


def test_prompt_does_not_eat_git_stdin(gg: GG, repo: Path) -> None:
    modify(gg, repo)
    rc, out, tty = run_with_tty(gg, ["git", "hash-object", "--stdin"], repo, "y",
                                stdin_data=b"hello\n")
    assert rc == 0, tty
    assert out.strip() == "ce013625030ba8dba906f756967f9e9ca394464a"


def test_no_prompt_without_tty(gg: GG, repo: Path) -> None:
    modify(gg, repo)
    r = gg.run("git", "status", cwd=repo)            # neither tty nor interactive stdin
    assert r.blocked and "On branch" not in r.out and "gitguard trust" in r.err
    assert "[y/N]" not in r.err


def test_no_prompt_when_disabled(gg: GG, repo: Path) -> None:
    modify(gg, repo)
    rc, out, tty = run_with_tty(gg, ["git", "status"], repo, "y", env={"GITGUARD_NO_PROMPT": "1"})
    assert rc != 0 and "[y/N]" not in tty and "On branch" not in out


def test_no_prompt_when_stderr_not_tty(gg: GG, repo: Path) -> None:
    """stderr redirected: the diff was not seen, no question."""
    import pty, fcntl, termios
    modify(gg, repo)
    master, slave = pty.openpty()

    def preexec() -> None:
        os.setsid()
        fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
    p = subprocess.Popen([sys.executable, str(GITGUARD), "git", "status"], cwd=repo, env=gg.env,
                         stdin=slave, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         preexec_fn=preexec, close_fds=True)
    os.close(slave)
    os.write(master, b"y\n")
    out, errb = p.communicate(timeout=30)
    os.close(master)
    assert p.returncode != 0 and b"On branch" not in out and b"[y/N]" not in errb


def test_no_prompt_for_never_trusted(gg: GG, tmp_path: Path) -> None:
    r = tmp_path / "fresh"
    assert gg.git("init", "-q", str(r)).rc == 0
    rc, out, tty = run_with_tty(gg, ["git", "status"], r, "y")
    assert rc != 0 and "[y/N]" not in tty and "never trusted" in tty


def test_no_prompt_for_structural_refusal(gg: GG, repo: Path) -> None:
    (repo / ".git/hooks/evil").symlink_to("/etc/passwd")
    gg.git("config", "core.hooksPath", ".git/hooks", cwd=repo)
    rc, out, tty = run_with_tty(gg, ["git", "status"], repo, "y")
    assert rc != 0 and "[y/N]" not in tty and "On branch" not in out
