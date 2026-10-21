"""Commands: trust/diff/restore, auto-trust clone/init, global options, management."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from tests.attacks._helpers import make_source
from tests.conftest import GG, REAL_GIT, write_exec


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
    assert r.rc == 0 and "config" in r.out and "pager" in r.out and not r.err


def test_trust_revalidates(gg: GG, repo: Path) -> None:
    gg.git("config", "core.pager", "cat", cwd=repo)
    assert gg.check(repo).blocked
    gg.trust(repo)
    assert not gg.check(repo).blocked


def test_trust_mentions_worktree_refs(gg: GG, repo: Path) -> None:
    (repo / ".githooks").mkdir()
    gg.git("config", "core.hooksPath", ".githooks", cwd=repo)
    r = gg.trust(repo)
    assert ".githooks" in r.out


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


def test_restore_leaves_a_planted_include_target_but_cleans_the_rest(gg: GG, repo: Path) -> None:
    """A container plants a hook, an include.path into the tree and the file it
    names. restore puts config and hooks back and leaves the included file in
    place (never a deletion outside the trusted roots), named in a warning;
    the repository is back in the trusted state since nothing names it any more."""
    write_exec(repo / ".git/hooks/pre-commit")
    with (repo / ".git/config").open("a") as f:
        f.write("[core]\n\tfsmonitor = /tmp/evil\n[include]\n\tpath = ../evil.inc\n")
    (repo / "evil.inc").write_text("[core]\n\tpager = sh -c 'id; cat'\n")
    assert gg.check(repo).blocked
    r = gg.run("restore", "-y", cwd=repo)
    assert r.rc == 0, r.err
    assert "evil.inc" in r.err and "left in place" in r.err
    assert (repo / "evil.inc").exists()
    assert not (repo / ".git/hooks/pre-commit").exists()
    assert "fsmonitor" not in (repo / ".git/config").read_text()
    assert not gg.check(repo).blocked


def test_restore_never_deletes_outside_the_trusted_roots(gg: GG, repo: Path, tmp_path: Path) -> None:
    """hooksPath redirected after the trust to a directory outside the repository
    (a stand-in for $HOME): the files there are not deleted, the config is
    restored, and with nothing else to restore the command says so."""
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    (outside / "precious").write_text("keep me\n")
    write_exec(outside / "pre-commit")
    gg.git("config", "core.hooksPath", str(outside), cwd=repo)
    assert gg.check(repo).blocked
    r = gg.run("restore", "-y", cwd=repo)
    assert r.rc == 0, r.err
    assert (outside / "precious").read_text() == "keep me\n"
    assert (outside / "pre-commit").exists()
    assert "left in place" in r.err
    assert gg.git("config", "core.hooksPath", cwd=repo).rc != 0
    assert not gg.check(repo).blocked


def test_config_diff_keeps_a_lone_cr_inside_its_line(gg: GG, repo: Path) -> None:
    """[53] The diff shown before [y/N] split lines in text mode: a lone CR became
    a line break, so `hooksPath = .githooks<CR>x = y` showed as two clean lines,
    `hooksPath = .githooks` and `x = y`, while git reads ONE value naming another
    directory. Lines are split on LF only, as git does; CRLF stays a line end."""
    cfg = repo / ".git/config"
    cfg.write_bytes(cfg.read_bytes() + b"[core]\r\n\thooksPath = .githooks\rx = y\n")
    r = gg.run("diff", cwd=repo)
    lines = r.out.splitlines()
    assert any("+?hooksPath = .githooks?x = y" in l for l in lines), r.out
    assert not any(l.strip() in ("+x = y", "x = y") for l in lines), r.out
    assert any(l.strip() == "+[core]" for l in lines), "CRLF must read as a plain line end"


def test_restore_noop(gg: GG, repo: Path) -> None:
    r = gg.run("restore", "-y", cwd=repo)
    assert r.rc == 0 and "nothing to restore" in r.out


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


def test_private_ext_file_is_watched_but_never_copied_nor_restored(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[56] A file outside the tree named by a program key (`core.sshCommand =
    ssh -i <key>`) is watched — the generic rule cannot tell a key from a
    script — but a private one (no read bit for group/other) is never copied
    into the state directory, and `restore` leaves it alone: it used to write
    the old private key over a rotated one. Positive control: an ext hook
    (0755) is still backed up and restored."""
    key = tmp_path / "sshkey"
    key.write_text("SECRET\n")
    key.chmod(0o600)
    hooks = tmp_path / "hooks"
    write_exec(hooks / "pre-commit")
    assert gg.git("config", "core.sshCommand", f"ssh -i {key}", cwd=repo).rc == 0
    assert gg.git("config", "core.hooksPath", str(hooks), cwd=repo).rc == 0
    r = gg.trust(repo)
    assert f"ext:{key}" in r.text and f"ext:{hooks}" in r.text, r.text
    bak = Path(str(gg.key_for(repo)) + ".d") / "ext"
    assert (bak / str(hooks).lstrip("/") / "pre-commit").is_file()
    assert not (bak / str(key).lstrip("/")).exists(), "the private key was copied"
    key.write_text("ROTATED\n")
    (hooks / "pre-commit").write_text("#!/bin/sh\nevil\n")
    r = gg.check(repo)
    assert r.blocked and f"modified  ext:{key}" in r.err and f"modified  ext:{hooks}/pre-commit" in r.err, r.err
    r = gg.run("restore", "-y", cwd=repo)
    assert r.rc == 0, r.text
    assert "private file" in r.text and str(key) in r.text, r.text
    assert key.read_text() == "ROTATED\n", "restore wrote the old private key back"
    assert (hooks / "pre-commit").read_text() == "#!/bin/sh\nid\n", "the ext hook was not restored"
    r = gg.check(repo)                   # only the rotated key still differs
    assert r.blocked and f"ext:{key}" in r.err and "pre-commit" not in r.err, r.err


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
def _python_only_dir(tmp_path: Path) -> Path:
    """A PATH directory holding `python3` (gitguard's shebang) and nothing else:
    `sys.executable`'s own directory is `/usr/bin` on a system Python, where git
    lives too."""
    import sys
    d = tmp_path / "pyonly"
    d.mkdir(exist_ok=True)
    link = d / "python3"
    if not link.is_symlink():
        os.symlink(sys.executable, link)
    return d


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


def test_transport_symlinks_pass_through(gg: GG, repo: Path, tmp_path: Path) -> None:
    """Debian's `/usr/bin/git-upload-pack` → `git`: with `/usr/bin/git → gitguard`
    sshd runs gitguard under that name for every fetch/push to the machine. It
    serves a repository named by argument and runs nothing of the caller's:
    passed to the real git, whatever the cwd's state."""
    import subprocess
    from tests.conftest import GITGUARD
    bare = tmp_path / "srv.git"
    assert gg.git("init", "-q", "--bare", str(bare)).rc == 0
    b = tmp_path / "bin"
    b.mkdir(exist_ok=True)
    link = b / "git-upload-pack"
    os.symlink(GITGUARD, link)
    write_exec(repo / ".git/hooks/pre-commit")           # cwd modified: irrelevant here
    r = subprocess.run([str(link), "--advertise-refs", str(bare)], cwd=repo, env=gg.env,
                       capture_output=True)
    assert r.returncode == 0, r.stderr
    assert b"gitguard" not in r.stderr
    assert gg.check(repo).blocked                         # the ordinary check still does


def test_version_passes_on_a_modified_repository(gg: GG, repo: Path) -> None:
    """`git --version` reads no repository; lazygit and fugitive run it first and
    took gitguard's refusal for an old git."""
    write_exec(repo / ".git/hooks/pre-commit")
    assert gg.run("git", "status", cwd=repo).blocked
    r = gg.run("git", "--version", cwd=repo)
    assert r.rc == 0 and r.out.startswith("git version"), r.text
    r = gg.run("git", "version", cwd=repo)
    assert r.rc == 0 and r.out.startswith("git version"), r.text
    link = _git_symlink(repo.parent)
    import subprocess
    r = subprocess.run([str(link), "--version"], cwd=repo, env=gg.env, capture_output=True, text=True)
    assert r.returncode == 0 and r.stdout.startswith("git version"), r.stderr


def test_version_runs_nothing_of_the_repository(gg: GG, repo: Path, tmp_path: Path) -> None:
    """The proof behind the passthrough: `git version` has no RUN_SETUP, so a
    `pager.version` or `core.pager` planted in the repository is not read.
    Positive control: `git -p version` is not on the list and is checked."""
    import subprocess
    marker = tmp_path / "PWNED"
    pager = tmp_path / "pager.sh"
    pager.write_text(f"#!/bin/sh\ntouch {marker}\ncat\n")
    pager.chmod(0o755)
    cfg = repo / ".git/config"
    cfg.write_text(cfg.read_text() + f"[core]\n\tpager = {pager}\n[pager]\n\tversion = true\n")
    assert gg.run("git", "status", cwd=repo).blocked           # the repository is modified
    r = subprocess.run([REAL_GIT, "version"], cwd=repo, env=gg.env, capture_output=True, text=True)
    assert r.returncode == 0 and not marker.exists()          # git itself reads nothing
    r = gg.run("git", "version", cwd=repo)
    assert r.rc == 0 and r.out.startswith("git version") and not marker.exists()
    assert gg.run("git", "-p", "version", cwd=repo).blocked    # a global option first: checked


def test_symlink_named_git_ahead_in_path_finds_the_real_git(gg: GG, repo: Path, tmp_path: Path) -> None:
    """Deployment `~/bin/git → gitguard` ahead in the PATH, no GITGUARD_REAL_GIT:
    the real git is the next one in the PATH, not gitguard again."""
    import subprocess
    link = _git_symlink(tmp_path)
    env = dict(gg.env, PATH=f"{link.parent}{os.pathsep}{gg.env['PATH']}")
    r = subprocess.run([str(link), "rev-parse", "--is-inside-work-tree"], cwd=repo, env=env,
                       capture_output=True, text=True)
    assert r.returncode == 0 and r.stdout.strip() == "true", r.stderr
    import sys
    nogit = f"{link.parent}{os.pathsep}{_python_only_dir(tmp_path)}"     # python3, no git
    r = subprocess.run([str(link), "status"], cwd=repo, env=dict(env, PATH=nogit),
                       capture_output=True, text=True)
    assert r.returncode != 0 and "GITGUARD_REAL_GIT" in r.stderr, r.stderr   # no other git: refuse


def test_sibling_git_real_wins_over_path(gg: GG, repo: Path, tmp_path: Path) -> None:
    """System-wide layout: `/usr/bin/git → gitguard`, the real git diverted to
    `/usr/bin/git.real`. Found without GITGUARD_REAL_GIT (cron, systemd and
    GUIs get no environment variable), and ahead of any other git in the PATH:
    that is the git the user would have run."""
    import shutil
    import subprocess
    link = _git_symlink(tmp_path)
    real = shutil.which("git", path=gg.env["PATH"])
    shim = link.parent / "git.real"
    shim.write_text(f'#!/bin/sh\necho GIT_REAL_SHIM >&2\nexec "{real}" "$@"\n')
    shim.chmod(0o755)
    # The fingerprint includes the system config of the git in use (derived
    # from its path): re-trust with that git so the comparison is like for like.
    import sys
    from tests.conftest import GITGUARD
    t = subprocess.run([sys.executable, str(GITGUARD), "trust"], cwd=repo,
                       env=dict(gg.env, GITGUARD_REAL_GIT=str(shim)), capture_output=True, text=True)
    assert t.returncode == 0, t.stderr
    r = subprocess.run([str(link), "rev-parse", "--is-inside-work-tree"], cwd=repo, env=gg.env,
                       capture_output=True, text=True)
    assert r.returncode == 0 and r.stdout.strip() == "true", r.stderr
    assert "GIT_REAL_SHIM" in r.stderr, r.stderr
    shim.unlink()
    nogit = f"{link.parent}{os.pathsep}{_python_only_dir(tmp_path)}"     # python3, no git
    r = subprocess.run([str(link), "status"], cwd=repo, env=dict(gg.env, PATH=nogit),
                       capture_output=True, text=True)
    assert r.returncode != 0, r.stdout
    assert "git.real" in r.stderr and "GITGUARD_REAL_GIT" in r.stderr, r.stderr


def test_sibling_git_real_must_not_be_gitguard(gg: GG, repo: Path, tmp_path: Path) -> None:
    """A `git.real` that resolves to gitguard itself is skipped (no exec loop);
    the PATH scan then finds the real git."""
    import subprocess
    from tests.conftest import GITGUARD
    link = _git_symlink(tmp_path)
    os.symlink(GITGUARD, link.parent / "git.real")
    r = subprocess.run([str(link), "rev-parse", "--is-inside-work-tree"], cwd=repo, env=gg.env,
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0 and r.stdout.strip() == "true", r.stderr


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
    out = gg.run("list").out
    lines = {l.split()[0]: l for l in out.splitlines() if l.strip()}
    assert "ok" in lines and str(m1) in lines["ok"]
    assert "modified" in lines and str(m2) in lines["modified"]
    assert "missing" in lines and str(m3) in lines["missing"]


def test_prune_and_forget(gg: GG, tmp_path: Path) -> None:
    import shutil
    m1, m2 = _mk(gg, tmp_path, "m1"), _mk(gg, tmp_path, "m2")
    shutil.rmtree(m2)
    gg.run("prune")
    assert "m2" not in gg.run("list").out
    idx = Path(str(gg.key_for(m1)) + ".idx")
    (m1 / "f").write_text("x\n")
    assert gg.git("add", "f", cwd=m1).rc == 0          # creates .git/index
    assert not gg.check(m1).blocked
    assert idx.is_file(), "gitlink cache written by the check"
    gg.run("forget", str(m1))
    assert "m1" not in gg.run("list").out
    assert not idx.exists(), "forget also removes the index cache"
    assert gg.check(m1).blocked, "forget → never trusted again"
    assert "not registered" in gg.run("forget", str(m1)).err


def test_retrust_skips_modified(gg: GG, tmp_path: Path) -> None:
    import shutil
    m1, m2 = _mk(gg, tmp_path, "m1"), _mk(gg, tmp_path, "m2")
    gg.git("config", "core.fsmonitor", "/tmp/evil", cwd=m2)
    shutil.rmtree(gg.key_for(m1).with_suffix(".d"), ignore_errors=True)
    shutil.rmtree(str(gg.key_for(m1)) + ".d", ignore_errors=True)
    assert "legacy" in gg.run("list").out
    gg.run("retrust")
    assert (Path(str(gg.key_for(m1)) + ".d")).is_dir()
    assert "modified" in gg.run("list").out, "m2 must not be re-trusted"


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


# ------------------------------------------ pass 8: exec-mode parsing, auto-trust
def test_config_env_then_dash_C_checks_target(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[40] `--config-env k=V -C <trapped>`: --config-env was taken for the
    subcommand, the -C ignored, and gitguard checked the cwd (no repository)."""
    gg.git("config", "core.fsmonitor", "/tmp/evil", cwd=repo)
    r = gg.run("git", "--config-env", "user.name=HOME", "-C", str(repo), "status", cwd=tmp_path)
    assert r.blocked and "On branch" not in r.out


def test_gitdir_before_dash_C_checks_target(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[41] `--git-dir=.git -C <trapped>` run from another trusted repository:
    gitguard resolved .git against the cwd, git against the -C target."""
    other = tmp_path / "other"
    gg.git("init", "-q", str(other))
    gg.trust(other)
    gg.git("config", "core.fsmonitor", "/tmp/evil", cwd=repo)
    r = gg.run("git", "--git-dir=.git", "-C", str(repo), "status", cwd=other)
    assert r.blocked and "On branch" not in r.out


def _tpl(tmp_path: Path) -> Path:
    tpl = tmp_path / "tpl"
    write_exec(tpl / "hooks/post-checkout")
    return tpl


def test_clone_templatedir_in_included_global_config_no_autotrust(gg: GG, tmp_path: Path) -> None:
    """[42] init.templateDir set in a file included by ~/.gitconfig"""
    src, tpl = make_source(gg, tmp_path), _tpl(tmp_path)
    inc = Path(gg.env["HOME"]) / "extra.cfg"
    inc.write_text(f"[init]\n\ttemplateDir = {tpl}\n")
    gg.git("config", "--global", "include.path", str(inc))
    res = gg.run("git", "clone", "-q", str(src), "c", cwd=tmp_path)
    assert res.rc == 0 and (tmp_path / "c/.git/hooks/post-checkout").exists()
    assert gg.check(tmp_path / "c").blocked


def test_clone_templatedir_dash_c_no_autotrust(gg: GG, tmp_path: Path) -> None:
    """[42] `git -c init.templateDir=… clone`"""
    src, tpl = make_source(gg, tmp_path), _tpl(tmp_path)
    res = gg.run("git", "-c", f"init.templateDir={tpl}", "clone", "-q", str(src), "c", cwd=tmp_path)
    assert res.rc == 0 and (tmp_path / "c/.git/hooks/post-checkout").exists()
    assert gg.check(tmp_path / "c").blocked


def test_clone_git_template_dir_env_no_autotrust(gg: GG, tmp_path: Path) -> None:
    """[42] GIT_TEMPLATE_DIR in the environment"""
    src, tpl = make_source(gg, tmp_path), _tpl(tmp_path)
    gg.env["GIT_TEMPLATE_DIR"] = str(tpl)
    res = gg.run("git", "clone", "-q", str(src), "c", cwd=tmp_path)
    assert res.rc == 0 and (tmp_path / "c/.git/hooks/post-checkout").exists()
    assert gg.check(tmp_path / "c").blocked


def test_clone_config_parameters_env_no_autotrust(gg: GG, tmp_path: Path) -> None:
    """[42] init.templateDir through GIT_CONFIG_COUNT/KEY/VALUE"""
    src, tpl = make_source(gg, tmp_path), _tpl(tmp_path)
    gg.env.update(GIT_CONFIG_COUNT="1", GIT_CONFIG_KEY_0="init.templateDir",
                  GIT_CONFIG_VALUE_0=str(tpl))
    res = gg.run("git", "clone", "-q", str(src), "c", cwd=tmp_path)
    assert res.rc == 0 and (tmp_path / "c/.git/hooks/post-checkout").exists()
    assert gg.check(tmp_path / "c").blocked


@pytest.mark.xfail(strict=True, reason="[44] open: the check runs before git updates the tree")
def test_checkout_rewrites_tracked_hook_then_runs_it(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[44] OPEN — core.hooksPath in the tree (husky, .githooks) and hooks
    tracked by git. refs/ and objects/ are volatile: the container commits a
    rewritten post-checkout on a branch. The state is clean when gitguard
    checks; `git checkout feat` writes the new hook, then runs it."""
    mark = tmp_path / "RAN"
    write_exec(repo / ".githooks/post-checkout", "#!/bin/sh\nexit 0\n")
    gg.git("add", ".githooks", cwd=repo)
    gg.git("commit", "-qm", "hooks", cwd=repo)
    gg.git("config", "core.hooksPath", ".githooks", cwd=repo)
    gg.trust(repo)
    # the container
    gg.git("checkout", "-q", "-b", "feat", cwd=repo)
    write_exec(repo / ".githooks/post-checkout", f"#!/bin/sh\ntouch '{mark}'\n")
    gg.git("commit", "-qam", "evil", cwd=repo)
    gg.git("checkout", "-q", "main", cwd=repo)
    assert not mark.exists() and not gg.check(repo).blocked
    # the user
    gg.run("git", "checkout", "-q", "feat", cwd=repo)
    assert not mark.exists(), "post-checkout from the container's commit was executed"


def test_trust_warns_hooks_in_tree(gg: GG, repo: Path) -> None:
    """[44] open flaw made visible: hooks under core.hooksPath in the tree."""
    write_exec(repo / ".githooks/pre-commit", "#!/bin/sh\nexit 0\n")
    gg.git("config", "core.hooksPath", ".githooks", cwd=repo)
    r = gg.run("trust", cwd=repo)
    assert r.rc == 0 and "hooks in the work tree (.githooks)" in r.err, r.text
    assert "hooks in the work tree" not in gg.run("trust", cwd=gg_plain(gg, repo)).err


def gg_plain(gg: GG, repo: Path) -> Path:
    p = repo.parent / "plain"
    gg.git("init", "-q", str(p))
    return p


# ------------------------------------------------ pass 9: discovery parity [49]
def test_invalid_dotgit_dir_is_walked_past(gg: GG, repo: Path) -> None:
    """[49] a `.git` directory git does not recognise is skipped: `trust`
    and the check from there concern the parent repository, as for git."""
    src = repo / "src"
    (src / ".git").mkdir(parents=True)
    (src / ".git/config").write_text("[core]\n\tfsmonitor = /tmp/evil\n")
    assert not gg.check(src).blocked                       # the parent is trusted and clean
    r = gg.run("trust", cwd=src)
    assert r.rc == 0 and str(repo) in r.out and not gg.key_for(src).exists(), r.text
    gg.git("config", "core.fsmonitor", "/tmp/evil", cwd=repo)
    assert gg.check(src).blocked                           # the parent's trap is seen from src


def test_core_worktree_keeps_the_key(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[47] core.worktree redirects the tree, not the identity of the
    repository: the state stays keyed on the directory holding .git, and a
    core.worktree added by the sandbox is an ordinary config change (diff)."""
    other = tmp_path / "other"
    other.mkdir()
    gg.git("config", "core.worktree", str(other), cwd=repo)
    r = gg.check(repo)
    assert r.blocked and "worktree = " in r.err and "never trusted" not in r.err, r.text
    assert f"{repo}/.git has changed" in r.err, r.text   # named by its .git, not by the tree
    gg.trust(repo)
    assert gg.key_for(repo).exists() and not gg.key_for(other).exists()
    assert gg.run("list").out.startswith("ok ")


# ------------------------------------------------------------ safe.bareRepository
NEEDLE = "safe.bareRepository"


def test_safe_bare_warning_at_trust_retrust_list(gg: GG, repo: Path) -> None:
    assert NEEDLE in gg.run("trust", cwd=repo).err
    assert NEEDLE in gg.run("list").err
    assert NEEDLE in gg.run("retrust").err
    assert NEEDLE not in gg.check(repo).err, "not on every command"
    assert NEEDLE not in gg.run("git", "status", cwd=repo).err
    assert gg.git("config", "--global", "safe.bareRepository", "explicit").rc == 0
    for r in (gg.run("trust", cwd=repo), gg.run("list"), gg.run("retrust")):
        assert r.rc == 0 and NEEDLE not in r.err, r.text


def test_safe_bare_parsed_without_git(gg: GG, repo: Path) -> None:
    """Value read by our parser: key case, last value wins, any value other
    than `explicit` → warning."""
    import gitguard as m
    home = Path(gg.env["HOME"])
    cfg = home / ".gitconfig"
    cfg.write_text(cfg.read_text() + "[Safe]\n\tBareRepository = Explicit\n")
    assert NEEDLE not in gg.run("list").err
    cfg.write_text(cfg.read_text() + "[safe]\n\tbareRepository = all\n")
    assert NEEDLE in gg.run("list").err
    assert m.safe_bare_explicit.__doc__        # public function, exercised above via list


# ------------------------------------------------------------ command line
@pytest.mark.parametrize("args", [["tust"], ["trust", "--dry-run"], ["diff", "x"], ["list", "x"],
                                  ["retrust", "x"], ["prune", "--all"], ["restore", "-y", "x"]])
def test_unknown_command_or_extra_argument_refused(gg: GG, repo: Path, args: list[str]) -> None:
    """`gitguard tust` used to run a silent check and exit 0, which looked
    like a successful `trust`."""
    r = gg.run(*args, cwd=repo)
    assert r.rc == 1 and ("unknown command" in r.err or "takes no argument" in r.err), r.text
    assert gg.check(repo).blocked is False


def test_management_output_on_stdout_warnings_on_stderr(gg: GG, repo: Path, tmp_path: Path) -> None:
    """`gitguard list | grep` must work: the result of a management command
    goes to stdout; warnings (safe.bareRepository…) and refusals to stderr;
    in exec mode and for the bare check, everything to stderr (stdout is git's)."""
    r = gg.run("list")
    assert r.out.startswith("ok ") and "safe.bareRepository" in r.err and "ok " not in r.err
    gg.git("config", "core.pager", "cat", cwd=repo)
    r = gg.run("diff", cwd=repo)
    assert "pager" in r.out and r.err == ""
    r = gg.check(repo)
    assert r.blocked and r.out == "" and "has changed" in r.err
    r = gg.run("git", "status", cwd=repo)
    assert r.blocked and r.out == "" and "has changed" in r.err
    r = gg.run("tust", cwd=repo)
    assert r.blocked and r.out == "" and "unknown command" in r.err


# ------------------------------------------------- the backup matches what was blessed
def test_save_trust_refuses_when_a_file_moved_after_the_diff(gg: GG, repo: Path, monkeypatch) -> None:
    """Between the diff and the answer, the sandbox rewrites a watched file:
    the blessed manifest would refuse it later, but the backup would hold the
    attacker's copy for `restore`. The copy is verified against the manifest."""
    import gitguard as gg_mod
    monkeypatch.setattr(gg_mod, "STATE", gg.state)
    r = gg_mod.open_repo(repo)
    refs = gg_mod.config_refs(r)
    new = gg_mod.manifest(r, refs)                      # the state "shown"
    before = gg.key_for(repo).read_bytes()
    gg.git("config", "core.fsmonitor", "/tmp/evil", cwd=repo)   # moved after the diff
    with pytest.raises(gg_mod.Refuse, match="changed while the question was pending"):
        gg_mod.save_trust(r, refs, new)
    assert gg.key_for(repo).read_bytes() == before, "reference untouched"
    assert not Path(str(gg.key_for(repo)) + ".d.tmp").exists()
    assert not Path(str(gg.key_for(repo)) + ".tmp").exists()
    assert gg.check(repo).blocked


# ---------------------------------------------------------- trust shows the diff
def test_trust_shows_the_diff_without_a_terminal(gg: GG, repo: Path) -> None:
    gg.git("config", "core.pager", "cat", cwd=repo)
    r = gg.run("trust", cwd=repo)
    assert r.rc == 0 and "pager = cat" in r.out and "has changed" in r.err, r.text
    assert not gg.check(repo).blocked


def test_trust_asks_on_a_terminal(gg: GG, repo: Path) -> None:
    from tests.test_prompt import run_with_tty
    gg.git("config", "core.pager", "cat", cwd=repo)
    rc, _, tty = run_with_tty(gg, ["trust"], repo, "n")
    assert rc != 0 and "[y/N]" in tty and "pager = cat" in tty, tty
    assert gg.check(repo).blocked, "not trusted"
    rc, _, tty = run_with_tty(gg, ["trust"], repo, "y")
    assert rc == 0, tty
    assert not gg.check(repo).blocked


def test_trust_of_an_unchanged_repo_asks_nothing(gg: GG, repo: Path) -> None:
    from tests.test_prompt import run_with_tty
    rc, _, tty = run_with_tty(gg, ["trust"], repo, None)
    assert rc == 0 and "[y/N]" not in tty, tty
