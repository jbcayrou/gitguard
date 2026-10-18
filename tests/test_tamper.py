"""[51] Modified during git's run, then put back: ctime is the witness.

The sandbox cannot be frozen (podman, a VM, anything): a watched file edited
between the check and git's read, then restored, passed every check. ctime
cannot be set from user space; the post-run snapshot sees it move.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from tests.conftest import GG, write_exec

MARK = "tampered"


def _sandbox_editor(tmp_path: Path, script: str) -> str:
    """A GIT_EDITOR that plays the sandbox while `git commit` waits for the
    message: runs `script` (python) then writes the message."""
    ed = tmp_path / "sandbox-editor.py"
    ed.write_text("import os, shutil, sys, time\nmsg = sys.argv[1]\n" + script
                  + "\nopen(msg, 'w').write('m\\n')\n")
    return f"{sys.executable} {ed}"


def _commit(gg: GG, repo: Path, editor: str):  # one commit with the sandbox as GIT_EDITOR
    (repo / "f").write_text(os.urandom(4).hex() + "\n")
    gg.git("add", "f", cwd=repo)
    return _run_with_editor(gg, repo, editor)


def _run_with_editor(gg: GG, repo: Path, editor: str):
    import subprocess
    from tests.conftest import GITGUARD, Result
    env = dict(gg.env, GIT_EDITOR=editor)
    r = subprocess.run([sys.executable, str(GITGUARD), "git", "commit"], cwd=repo, env=env,
                       capture_output=True, text=True, errors="replace")
    return Result(r.returncode, r.stdout, r.stderr)


RESTORE_CONFIG = """
cfg = '.git/config'
orig = open(cfg, 'rb').read()
st = os.stat(cfg)
open(cfg, 'ab').write(b'[core]\\n\\tfsmonitor = /tmp/evil\\n')
time.sleep(0.01)
open(cfg, 'wb').write(orig)
os.utime(cfg, ns=(st.st_atime_ns, st.st_mtime_ns))   # mtime forged back
"""


def test_config_modified_then_restored_is_detected(gg: GG, repo: Path, tmp_path: Path) -> None:
    r = _commit(gg, repo, _sandbox_editor(tmp_path, RESTORE_CONFIG))
    assert r.rc == 0, r.text                               # git ran (detection, not prevention)
    assert "put back" in r.err and ".git/config" in r.err, r.text
    marker = Path(str(gg.key_for(repo)) + ".tampered")
    assert marker.is_file() and ".git/config" in marker.read_text()
    # Sticky: every command refuses until trust/restore, and `list` says so.
    r = gg.check(repo)
    assert r.blocked and MARK in r.err and "previous git run" in r.err, r.text
    r = gg.run("git", "status", cwd=repo)
    assert r.blocked and "On branch" not in r.out and MARK in r.err
    assert gg.run("list").out.startswith("tampered")
    gg.trust(repo)
    assert not marker.exists() and not gg.check(repo).blocked


def test_hook_dropped_then_removed_is_detected(gg: GG, repo: Path, tmp_path: Path) -> None:
    """A transient hook in `.git/hooks/`: the directory's ctime moves while
    its watched entries do not."""
    script = """
h = '.git/hooks/post-commit'
open(h, 'w').write('#!/bin/sh\\ntouch %s\\n')
os.chmod(h, 0o755)
""" % (tmp_path / "RAN")
    # the hook stays during the commit (git runs it), the sandbox removes it after:
    # simulated by a post-commit hook that deletes itself.
    script = """
h = '.git/hooks/post-commit'
open(h, 'w').write('#!/bin/sh\\ntouch %s\\nrm -f "$0"\\n')
os.chmod(h, 0o755)
""" % (tmp_path / "RAN")
    r = _commit(gg, repo, _sandbox_editor(tmp_path, script))
    assert r.rc == 0 and (tmp_path / "RAN").exists(), "control: the transient hook did run"
    assert not (repo / ".git/hooks/post-commit").exists()
    assert "put back" in r.err and "hooks/ (an entry added, then removed)" in r.err, r.text
    assert gg.check(repo).blocked


def test_tree_hook_modified_then_restored_is_detected(gg: GG, repo: Path, tmp_path: Path) -> None:
    """Same for a hooksPath in the tree (husky-like), scope wt."""
    write_exec(repo / ".githooks/pre-commit", "#!/bin/sh\nexit 0\n")
    gg.git("config", "core.hooksPath", ".githooks", cwd=repo)
    gg.trust(repo)
    script = """
h = '.githooks/pre-commit'
orig = open(h, 'rb').read()
open(h, 'wb').write(b'#!/bin/sh\\ntouch /tmp/evil\\n')
open(h, 'wb').write(orig)
"""
    r = _commit(gg, repo, _sandbox_editor(tmp_path, script))
    assert r.rc == 0 and ".githooks/pre-commit" in r.err and "put back" in r.err, r.text


def test_control_untouched_commit_has_no_marker(gg: GG, repo: Path, tmp_path: Path) -> None:
    r = _commit(gg, repo, _sandbox_editor(tmp_path, ""))
    assert r.rc == 0 and "put back" not in r.err, r.text
    assert not Path(str(gg.key_for(repo)) + ".tampered").exists()
    assert not gg.check(repo).blocked


def test_gits_own_config_write_is_not_tamper(gg: GG, repo: Path, tmp_path: Path) -> None:
    """`push -u` rewrites .git/config with another content: not "put back",
    left to the next command (auto-accept of branch tracking)."""
    bare = tmp_path / "remote.git"
    gg.git("init", "-q", "--bare", str(bare))
    gg.git("remote", "add", "origin", str(bare), cwd=repo)
    gg.trust(repo)
    r = gg.run("git", "push", "-q", "-u", "origin", "main", cwd=repo)
    assert r.rc == 0 and "put back" not in r.err, r.text
    assert not Path(str(gg.key_for(repo)) + ".tampered").exists()
    r = gg.run("git", "status", cwd=repo)
    assert r.rc == 0 and "branch tracking" in r.err, r.text


def _with_remote(gg: GG, repo: Path, tmp_path: Path) -> None:
    bare = tmp_path / "remote.git"
    gg.git("init", "-q", "--bare", str(bare))
    gg.git("remote", "add", "origin", str(bare), cwd=repo)
    gg.git("push", "-q", "-u", "origin", "main", cwd=repo)
    gg.git("config", "alias.pu", "push -u origin main", cwd=repo)
    gg.git("config", "alias.pu2", "pu", cwd=repo)                  # nested alias
    gg.trust(repo)


@pytest.mark.parametrize("args", [
    ["config", "core.pager", "cat"],
    ["push", "-q", "-u", "origin", "main"],          # already tracking: identical rewrite
    ["branch", "-u", "origin/main"],
    ["remote", "set-url", "origin", "SAME"],
    ["pu"], ["pu2"],                                  # aliases of push -u
], ids=lambda a: a[0])
def test_identical_config_rewrite_by_git_is_not_tamper(gg: GG, repo: Path, tmp_path: Path,
                                                       args: list[str]) -> None:
    """git rewrites config files as they are when the value is already there
    (`push -u` out of habit…): not reported for the subcommands that write
    config by design, aliases resolved."""
    gg.git("config", "core.pager", "cat", cwd=repo)
    _with_remote(gg, repo, tmp_path)
    args = [str(tmp_path / "remote.git") if a == "SAME" else a for a in args]
    r = gg.run("git", *args, cwd=repo)
    assert r.rc == 0 and "put back" not in r.err, r.text
    assert not gg.check(repo).blocked, gg.check(repo).text


def test_submodule_sync_and_update_are_not_tamper(gg: GG, repo: Path, tmp_path: Path) -> None:
    from tests.attacks._helpers import add_submodule
    add_submodule(gg, repo, tmp_path)
    gg.trust(repo)
    for args in (["submodule", "sync", "-q"], ["submodule", "update", "--init", "-q"]):
        r = gg.run("git", *args, cwd=repo)
        assert r.rc == 0 and "put back" not in r.err, (args, r.text)
    assert not gg.check(repo).blocked


def test_hook_touched_during_push_is_still_tamper(gg: GG, repo: Path, tmp_path: Path) -> None:
    """A config writer only exempts config files: a hook modified and put
    back during a `push` (here by the pre-push hook playing the sandbox) is
    reported."""
    write_exec(repo / ".git/hooks/post-checkout", "#!/bin/sh\nexit 0\n")
    victim = repo / ".git/hooks/post-checkout"
    write_exec(repo / ".git/hooks/pre-push",
               f"#!/bin/sh\ncp '{victim}' /tmp/gg-save.$$ && echo evil >> '{victim}' && "
               f"cp /tmp/gg-save.$$ '{victim}' && rm /tmp/gg-save.$$\nexit 0\n")
    _with_remote(gg, repo, tmp_path)
    (repo / "g").write_text("g\n")
    gg.git("add", "g", cwd=repo)
    gg.git("commit", "-qm", "g", cwd=repo)
    r = gg.run("git", "push", "-q", "-u", "origin", "main", cwd=repo)
    assert r.rc == 0 and "put back" in r.err and "post-checkout" in r.err, r.text
    assert gg.check(repo).blocked


def test_shell_alias_exempts_nothing(gg: GG, repo: Path, tmp_path: Path) -> None:
    """`alias.x = !…` is opaque: a config file put back during it is reported."""
    cfg = repo / ".git/config"
    gg.git("config", "alias.touchcfg", f"!sh -c 'cp {cfg} /tmp/gg-c.$$ && echo x >> {cfg} && "
                                       f"cp /tmp/gg-c.$$ {cfg} && rm /tmp/gg-c.$$'", cwd=repo)
    gg.trust(repo)
    r = gg.run("git", "touchcfg", cwd=repo)
    assert r.rc == 0 and "put back" in r.err and ".git/config" in r.err, r.text


def test_gc_and_commit_do_not_trip(gg: GG, repo: Path) -> None:
    """Volatile zones move all the time (objects/, index.lock in the root):
    no directory with a volatile sibling is judged."""
    for args in (["commit", "-q", "--allow-empty", "-m", "x"], ["gc", "-q"], ["stash", "list"],
                 ["maintenance", "run", "--quiet"]):
        r = gg.run("git", *args, cwd=repo)
        assert r.rc == 0 and "put back" not in r.err, (args, r.text)
    assert not gg.check(repo).blocked


def test_restore_clears_marker(gg: GG, repo: Path, tmp_path: Path) -> None:
    _commit(gg, repo, _sandbox_editor(tmp_path, RESTORE_CONFIG))
    marker = Path(str(gg.key_for(repo)) + ".tampered")
    assert marker.is_file()
    r = gg.run("restore", "-y", cwd=repo)
    assert r.rc == 0, r.text
    assert not marker.exists() and not gg.check(repo).blocked


def test_forget_removes_marker(gg: GG, repo: Path, tmp_path: Path) -> None:
    _commit(gg, repo, _sandbox_editor(tmp_path, RESTORE_CONFIG))
    marker = Path(str(gg.key_for(repo)) + ".tampered")
    assert marker.is_file()
    gg.run("forget", str(repo))
    assert not marker.exists()


def test_signal_exit_code(gg: GG, repo: Path, tmp_path: Path) -> None:
    """git killed by a signal: gitguard reports 128 + signal like a shell."""
    import signal, subprocess, time
    from tests.conftest import GITGUARD
    env = dict(gg.env, GIT_EDITOR=_sandbox_editor(tmp_path, "time.sleep(5)"))
    (repo / "f").write_text("z\n")
    gg.git("add", "f", cwd=repo)
    p = subprocess.Popen([sys.executable, str(GITGUARD), "git", "commit"], cwd=repo, env=env,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    for _ in range(50):                                   # wait for the git child
        time.sleep(0.1)
        kids = subprocess.run(["pgrep", "-P", str(p.pid)], capture_output=True, text=True).stdout.split()
        if kids:
            break
    assert kids, "git child not found"
    os.kill(int(kids[0]), signal.SIGTERM)
    p.wait(10)
    assert p.returncode == 128 + signal.SIGTERM, (p.returncode, p.stderr.read())
