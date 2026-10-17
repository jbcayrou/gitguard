"""Commands: trust/diff/restore, auto-trust clone/init, global options, management."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from tests.attacks._helpers import make_source
from tests.conftest import GG, write_exec


# ------------------------------------------------------------ trust / diff
def test_untrusted_repo_is_blocked(gg: GG, tmp_path: Path) -> None:
    r = tmp_path / "r"
    gg.git("init", "-q", str(r))
    res = gg.check(r)
    assert res.blocked and "never trusted" in res.err
    gg.trust(r)
    assert not gg.check(r).blocked


def test_diff_shows_change(gg: GG, repo: Path) -> None:
    gg.git("config", "core.pager", "cat", cwd=repo)
    r = gg.run("diff", cwd=repo)
    assert r.rc == 0 and "config" in r.err and "pager" in r.err


def test_trust_revalidates(gg: GG, repo: Path) -> None:
    gg.git("config", "core.pager", "cat", cwd=repo)
    assert gg.check(repo).blocked
    gg.trust(repo)
    assert not gg.check(repo).blocked


def test_trust_mentions_worktree_refs(gg: GG, repo: Path) -> None:
    (repo / ".githooks").mkdir()
    gg.git("config", "core.hooksPath", ".githooks", cwd=repo)
    r = gg.trust(repo)
    assert ".githooks" in r.err


# ------------------------------------------------------------------ restore
def test_restore_repairs_gitdir(gg: GG, repo: Path) -> None:
    gg.git("config", "core.fsmonitor", "/tmp/evil", cwd=repo)
    write_exec(repo / ".git/hooks/pre-commit")
    (repo / ".git/hooks/pre-push.sample").unlink()
    (repo / ".git/info/attributes").write_text("* filter=x\n")
    assert gg.check(repo).blocked
    assert gg.run("restore", "-y", cwd=repo).rc == 0
    assert not gg.check(repo).blocked
    assert not (repo / ".git/hooks/pre-commit").exists()
    assert (repo / ".git/hooks/pre-push.sample").exists()
    assert not (repo / ".git/info/attributes").exists()
    assert gg.git("config", "core.fsmonitor", cwd=repo).rc != 0
    (repo / "f").write_text("b\n")
    assert gg.git("commit", "-qam", "c2", cwd=repo).rc == 0, "repository still functional"


def test_restore_noop(gg: GG, repo: Path) -> None:
    r = gg.run("restore", "-y", cwd=repo)
    assert r.rc == 0 and "nothing to restore" in r.err


def test_restore_refuses_broken_structure(gg: GG, repo: Path, tmp_path: Path) -> None:
    (repo / ".git/refs").rename(repo / ".git/refs.bak")
    os.symlink(tmp_path / "home", repo / ".git/refs")
    assert gg.run("restore", "-y", cwd=repo).blocked


def test_restore_worktree_hook(gg: GG, repo: Path) -> None:
    write_exec(repo / ".githooks/pre-commit", "#!/bin/sh\nexit 0\n")
    gg.git("config", "core.hooksPath", ".githooks", cwd=repo)
    gg.trust(repo)
    write_exec(repo / ".githooks/pre-commit", "#!/bin/sh\necho PWNED\n")
    assert gg.run("restore", "-y", cwd=repo).rc == 0
    assert "exit 0" in (repo / ".githooks/pre-commit").read_text()
    assert not gg.check(repo).blocked


def test_restore_ext_path(gg: GG, repo: Path, tmp_path: Path) -> None:
    shared = tmp_path / "shared-hooks"
    shared.mkdir()
    gg.git("config", "core.hooksPath", "../shared-hooks", cwd=repo)
    gg.trust(repo)
    write_exec(shared / "pre-commit")
    assert gg.check(repo).blocked
    assert gg.run("restore", "-y", cwd=repo).rc == 0
    assert not gg.check(repo).blocked


def test_restore_does_not_write_through_symlink_file(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[3] restore must never overwrite the target of a planted symlink."""
    victim = tmp_path / "victim.txt"
    victim.write_text("SECRET\n")
    write_exec(repo / ".githooks/pre-commit", "#!/bin/sh\nexit 0\n")
    gg.git("config", "core.hooksPath", ".githooks", cwd=repo)
    gg.trust(repo)
    (repo / ".githooks/pre-commit").unlink()
    os.symlink(victim, repo / ".githooks/pre-commit")
    gg.run("restore", "-y", cwd=repo)
    assert victim.read_text() == "SECRET\n"
    assert not (repo / ".githooks/pre-commit").is_symlink()
    assert (repo / ".githooks/pre-commit").is_file()


def test_restore_refuses_symlinked_parent_dir(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[3] parent directory replaced by a symlink → refusal, nothing written."""
    write_exec(repo / ".githooks/pre-commit", "#!/bin/sh\nexit 0\n")
    gg.git("config", "core.hooksPath", ".githooks", cwd=repo)
    gg.trust(repo)
    import shutil
    shutil.rmtree(repo / ".githooks")
    evil = tmp_path / "evil"
    evil.mkdir()
    os.symlink(evil, repo / ".githooks")
    assert gg.run("restore", "-y", cwd=repo).blocked
    assert not (evil / "pre-commit").exists()


def test_restore_does_not_delete_head_via_injected_name(gg: GG, repo: Path) -> None:
    """[11] a malformed file name must not become an rm action."""
    (repo / ".githooks").mkdir()
    gg.git("config", "core.hooksPath", ".githooks", cwd=repo)
    gg.trust(repo)
    (repo / ".githooks" / "x\n644 abc HEAD").write_text("")
    gg.run("restore", "-y", cwd=repo)
    assert (repo / ".git/HEAD").exists()


def test_restore_asks_confirmation(gg: GG, repo: Path) -> None:
    gg.git("config", "core.pager", "cat", cwd=repo)
    r = gg.run("restore", cwd=repo, stdin="n\n")
    assert r.blocked and "aborted" in r.err
    assert gg.git("config", "core.pager", cwd=repo).out.strip() == "cat"


# ---------------------------------------------------- auto-trust clone/init
def test_clone_autotrust(gg: GG, tmp_path: Path) -> None:
    src = make_source(gg, tmp_path)
    r = gg.run("git", "clone", "-q", str(src), "c1", cwd=tmp_path)
    assert r.rc == 0 and "new repository trusted" in r.err
    assert not gg.check(tmp_path / "c1").blocked


def test_clone_autotrust_derived_name(gg: GG, tmp_path: Path) -> None:
    src = make_source(gg, tmp_path)
    import shutil
    shutil.copytree(src, tmp_path / "src.git")
    dst = tmp_path / "dst"
    dst.mkdir()
    assert gg.run("git", "clone", "-q", str(tmp_path / "src.git"), cwd=dst).rc == 0
    assert not gg.check(dst / "src").blocked


def test_init_autotrust(gg: GG, tmp_path: Path) -> None:
    assert gg.run("git", "init", "-q", "i1", cwd=tmp_path).rc == 0
    assert not gg.check(tmp_path / "i1").blocked


def test_init_via_dash_C(gg: GG, tmp_path: Path) -> None:
    (tmp_path / "i2").mkdir()
    assert gg.run("git", "-C", str(tmp_path / "i2"), "init", "-q", cwd=tmp_path).rc == 0
    assert not gg.check(tmp_path / "i2").blocked


def test_init_on_existing_trapped_git_no_autotrust(gg: GG, tmp_path: Path) -> None:
    r = tmp_path / "i3"
    gg.git("init", "-q", str(r))
    write_exec(r / ".git/hooks/pre-commit")
    res = gg.run("git", "init", "-q", "i3", cwd=tmp_path)
    assert res.rc == 0 and "no auto-trust" in res.err
    assert gg.check(r).blocked


def test_clone_template_no_autotrust(gg: GG, tmp_path: Path) -> None:
    src = make_source(gg, tmp_path)
    tpl = tmp_path / "tpl"
    write_exec(tpl / "hooks/pre-commit")
    res = gg.run("git", "clone", "-q", f"--template={tpl}", str(src), "c2", cwd=tmp_path)
    assert res.rc == 0 and "template" in res.err
    assert gg.check(tmp_path / "c2").blocked


def test_clone_bare_runs_without_trust(gg: GG, tmp_path: Path) -> None:
    src = make_source(gg, tmp_path)
    assert gg.run("git", "clone", "-q", "--bare", str(src), "b1", cwd=tmp_path).rc == 0
    assert (tmp_path / "b1").is_dir()


def test_failed_clone_propagates_rc(gg: GG, tmp_path: Path) -> None:
    r = gg.run("git", "clone", "-q", str(tmp_path / "nope"), "c3", cwd=tmp_path)
    assert r.rc != 0 and "trusted" not in r.err


# ----------------------------------------------------------- global options
def test_dash_C_trapped_repo_blocked(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[10] git -C <trapped> from elsewhere."""
    gg.git("config", "core.fsmonitor", "/tmp/evil", cwd=repo)
    assert gg.run("git", "-C", str(repo), "status", cwd=tmp_path).blocked


def test_git_dir_work_tree_blocked(gg: GG, repo: Path, tmp_path: Path) -> None:
    gg.git("config", "core.fsmonitor", "/tmp/evil", cwd=repo)
    r = gg.run("git", f"--git-dir={repo}/.git", f"--work-tree={repo}", "status", cwd=tmp_path)
    assert r.blocked


def test_dash_C_healthy_repo_runs(gg: GG, repo: Path, tmp_path: Path) -> None:
    r = gg.run("git", "-C", str(repo), "rev-parse", "--is-inside-work-tree", cwd=tmp_path)
    assert r.rc == 0 and r.out.strip() == "true"


def test_dash_C_relative_no_double_cd(gg: GG, repo: Path) -> None:
    (repo / "d").mkdir()
    r = gg.run("git", "-C", "d", "rev-parse", "--show-prefix", cwd=repo)
    assert r.rc == 0 and r.out.strip() == "d/"


def test_dash_C_without_argument_fails_closed(gg: GG, repo: Path) -> None:
    """Global option without an argument: clean refusal, no traceback, git not run."""
    r = gg.run("git", "-C", cwd=repo)
    assert r.blocked
    assert "Traceback" not in r.text
    assert "without an argument" in r.text


# -------------------------------------------------- symlink named git (wrapper)
def _git_symlink(tmp_path: Path) -> Path:
    from tests.conftest import GITGUARD
    b = tmp_path / "bin"
    b.mkdir(exist_ok=True)
    link = b / "git"
    if not link.is_symlink():
        os.symlink(GITGUARD, link)
    return link


def test_symlink_named_git_runs_git(gg: GG, repo: Path, tmp_path: Path) -> None:
    """Deployment `ln -s gitguard ~/bin/git`: argv[0] must not be passed to git."""
    import subprocess
    link = _git_symlink(tmp_path)
    r = subprocess.run([str(link), "-C", str(repo), "rev-parse", "--is-inside-work-tree"],
                       cwd=tmp_path, env=gg.env, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "true"


def test_symlink_named_git_blocks_trapped(gg: GG, repo: Path, tmp_path: Path) -> None:
    import subprocess
    link = _git_symlink(tmp_path)
    gg.git("config", "core.fsmonitor", "/tmp/evil", cwd=repo)
    r = subprocess.run([str(link), "status"], cwd=repo, env=gg.env, capture_output=True, text=True)
    assert r.returncode != 0
    assert "has changed" in r.stderr


# ------------------------------------------------- list / forget / retrust
def _mk(gg: GG, tmp_path: Path, name: str) -> Path:
    r = tmp_path / name
    gg.git("init", "-q", str(r))
    gg.trust(r)
    return r


def test_list_statuses(gg: GG, tmp_path: Path) -> None:
    import shutil
    m1, m2, m3 = (_mk(gg, tmp_path, n) for n in ("m1", "m2", "m3"))
    gg.git("config", "core.fsmonitor", "/tmp/evil", cwd=m2)
    shutil.rmtree(m3)
    out = gg.run("list").err
    lines = {l.split()[0]: l for l in out.splitlines() if l.strip()}
    assert "ok" in lines and str(m1) in lines["ok"]
    assert "modified" in lines and str(m2) in lines["modified"]
    assert "missing" in lines and str(m3) in lines["missing"]


def test_prune_and_forget(gg: GG, tmp_path: Path) -> None:
    import shutil
    m1, m2 = _mk(gg, tmp_path, "m1"), _mk(gg, tmp_path, "m2")
    shutil.rmtree(m2)
    gg.run("prune")
    assert "m2" not in gg.run("list").err
    idx = Path(str(gg.key_for(m1)) + ".idx")
    (m1 / "f").write_text("x\n")
    assert gg.git("add", "f", cwd=m1).rc == 0          # creates .git/index
    assert not gg.check(m1).blocked
    assert idx.is_file(), "gitlink cache written by the check"
    gg.run("forget", str(m1))
    assert "m1" not in gg.run("list").err
    assert not idx.exists(), "forget also removes the index cache"
    assert gg.check(m1).blocked, "forget → never trusted again"
    assert "not registered" in gg.run("forget", str(m1)).err


def test_retrust_skips_modified(gg: GG, tmp_path: Path) -> None:
    import shutil
    m1, m2 = _mk(gg, tmp_path, "m1"), _mk(gg, tmp_path, "m2")
    gg.git("config", "core.fsmonitor", "/tmp/evil", cwd=m2)
    shutil.rmtree(gg.key_for(m1).with_suffix(".d"), ignore_errors=True)
    shutil.rmtree(str(gg.key_for(m1)) + ".d", ignore_errors=True)
    assert "legacy" in gg.run("list").err
    gg.run("retrust")
    assert (Path(str(gg.key_for(m1)) + ".d")).is_dir()
    assert "modified" in gg.run("list").err, "m2 must not be re-trusted"


def test_help(gg: GG) -> None:
    r = gg.run("help")
    assert r.rc == 0 and "retrust" in r.out


def test_untrusted_message_colors_on_tty(gg: GG, tmp_path: Path) -> None:
    """On a terminal: colours emitted; in a pipe: none. In both cases the
    message's newline is a real newline."""
    import pty, select
    r = tmp_path / "r"
    gg.git("init", "-q", str(r))
    env = {k: v for k, v in gg.env.items() if k != "NO_COLOR"}
    master, slave = pty.openpty()
    import subprocess, sys
    from tests.conftest import GITGUARD
    p = subprocess.Popen([sys.executable, str(GITGUARD)], cwd=r, env=env,
                         stdout=slave, stderr=slave, stdin=slave, close_fds=True)
    os.close(slave)
    out = b""
    while True:
        rl, _, _ = select.select([master], [], [], 5)
        if not rl:
            break
        try:
            chunk = os.read(master, 4096)
        except OSError:
            break
        if not chunk:
            break
        out += chunk
    p.wait(5)
    text = out.decode("utf-8", "replace")
    assert p.returncode == 1
    assert "\x1b[36mgitguard trust\x1b[0m" in text, text
    assert "?[36m" not in text
    assert "\r\n  Inspect" in text or "\n  Inspect" in text, "the newline must be real"
    piped = gg.check(r)
    assert "\x1b" not in piped.err and "\n  Inspect" in piped.err


def test_no_color_and_sanitized_output(gg: GG, repo: Path) -> None:
    (repo / ".git/hooks" / "pre-commit\x1b[2Kfake").write_text("")
    r = gg.check(repo)
    assert r.blocked
    assert "\x1b" not in r.err, "no control code may be emitted"
    assert "pre-commit?[2Kfake" in r.err


def test_unreadable_watched_dir_refuses(gg: GG, repo: Path) -> None:
    """An unreadable watched directory (hooks/ at 0300) is not seen as empty."""
    h = repo / ".git/hooks"
    h.chmod(0o300)
    try:
        r = gg.check(repo)
        assert r.blocked and "unreadable" in r.text, r.text
    finally:
        h.chmod(0o755)


def test_git_from_inside_planted_bare_subdir_blocked(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[23] git run from a subdirectory that is itself a bare gitdir."""
    import shutil
    bare = tmp_path / "bare.git"
    assert gg.git("clone", "-q", "--bare", str(repo), str(bare)).rc == 0
    shutil.copytree(bare, repo / "src")
    mark = tmp_path / "EXEC"
    write_exec(repo / "src/hooks/reference-transaction", f"#!/bin/sh\ntouch {mark}\nexit 0\n")
    r = gg.run("git", "tag", "v9", cwd=repo / "src")
    assert r.blocked and "gitguard:" in r.err
    assert not mark.exists(), "the planted gitdir's hook was executed"


def test_bare_repo_is_refused(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[23] bare repository: not handled, explicit refusal rather than silent pass."""
    bare = tmp_path / "bare.git"
    assert gg.git("clone", "-q", "--bare", str(repo), str(bare)).rc == 0
    r = gg.run("git", "log", "--oneline", cwd=bare)
    assert r.blocked and "bare" in r.err


def test_git_dir_and_work_tree_from_elsewhere(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[28] --git-dir + --work-tree: the checked root is the work tree, not the cwd."""
    home = Path(gg.env["HOME"])
    gg.git("init", "-q", str(home / "x" / "other"))     # some .git under the cwd
    r = gg.run("git", f"--git-dir={repo}/.git", f"--work-tree={repo}", "rev-parse",
               "--show-toplevel", cwd=home)
    assert r.rc == 0 and Path(r.out.strip()).resolve() == repo.resolve(), r.text
    gg.git("config", "core.fsmonitor", "/tmp/evil", cwd=repo)
    r = gg.run("git", f"--git-dir={repo}/.git", f"--work-tree={repo}", "status", cwd=home)
    assert r.blocked and str(repo) in r.err and "nested" not in r.err


def test_git_dir_env_with_work_tree_env(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[28] GIT_DIR + GIT_WORK_TREE in the environment."""
    env = dict(gg.env, GIT_DIR=str(repo / ".git"), GIT_WORK_TREE=str(repo))
    import subprocess, sys
    from tests.conftest import GITGUARD
    r = subprocess.run([sys.executable, str(GITGUARD)], cwd=tmp_path, env=env,
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def test_trust_outside_repo_fails(gg: GG, tmp_path: Path) -> None:
    """[30] trust/diff/restore outside a repository: an error, not a silent exit 0."""
    for cmd in ("trust", "diff", "restore"):
        r = gg.run(cmd, cwd=tmp_path)
        assert r.blocked and "no git repository" in r.err, (cmd, r.text)
    assert not gg.check(tmp_path).blocked


def test_split_index_refused_explicitly(gg: GG, repo: Path) -> None:
    """[31] core.splitIndex: the gitlinks live in sharedindex.*, unread → clear refusal."""
    assert gg.git("update-index", "--split-index", cwd=repo).rc == 0
    r = gg.check(repo)
    assert r.blocked and "split" in r.err.lower(), r.text
