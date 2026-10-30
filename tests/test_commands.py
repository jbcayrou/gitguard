"""Commands: trust/diff/restore, auto-trust clone/init, global options, management."""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from tests.attacks._helpers import commit, make_source
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
    """[20] hooksPath redirected after the trust to a directory outside the
    repository (a stand-in for $HOME): the files there are not deleted, the
    config is restored, and with nothing else to restore the command says so."""
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


def test_restore_leaves_ext_paths_alone(gg: GG, repo: Path, tmp_path: Path) -> None:
    """A hooks directory outside the tree (`../shared-hooks`, scope `ext`) is
    watched, but restore neither writes nor deletes there and the state
    directory holds no copy of it: the planted hook is named and left, the
    repository stays refused until the user has looked at it."""
    shared = tmp_path / "shared-hooks"
    shared.mkdir()
    gg.git("config", "core.hooksPath", "../shared-hooks", cwd=repo)
    gg.trust(repo)
    assert not (Path(str(gg.key_for(repo)) + ".d") / "ext").exists()
    write_exec(shared / "pre-commit", "#!/bin/sh\nevil\n")
    assert gg.check(repo).blocked
    r = gg.run("restore", "-y", cwd=repo)
    assert r.rc != 0 and "nothing else to restore" in r.err, r.text
    assert f"ext:{shared}/pre-commit" in r.err and "left in place" in r.err, r.err
    assert (shared / "pre-commit").read_text() == "#!/bin/sh\nevil\n"
    assert gg.check(repo).blocked
    (shared / "pre-commit").unlink()                 # the user's repair
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
    script — but never copied into the state directory, and `restore` leaves
    it alone: it used to write the old private key over a rotated one. Since
    restore stopped acting outside the repository, the same holds for every
    `ext` entry, an ext hook included; a modified one keeps the repository
    refused until the user has dealt with it."""
    key = tmp_path / "sshkey"
    key.write_text("SECRET\n")
    key.chmod(0o600)
    hooks = tmp_path / "hooks"
    write_exec(hooks / "pre-commit")
    assert gg.git("config", "core.sshCommand", f"ssh -i {key}", cwd=repo).rc == 0
    assert gg.git("config", "core.hooksPath", str(hooks), cwd=repo).rc == 0
    r = gg.trust(repo)
    assert f"ext:{key}" in r.text and f"ext:{hooks}" in r.text, r.text
    bak = Path(str(gg.key_for(repo)) + ".d")
    assert not (bak / "ext").exists(), "an ext file was copied into the state directory"
    assert (bak / "local/config").is_file()
    key.write_text("ROTATED\n")
    (hooks / "pre-commit").write_text("#!/bin/sh\nevil\n")
    r = gg.check(repo)
    assert r.blocked and f"modified  ext:{key}" in r.err and f"modified  ext:{hooks}/pre-commit" in r.err, r.err
    r = gg.run("restore", "-y", cwd=repo)
    assert r.rc != 0 and "nothing else to restore" in r.err, r.text
    assert str(key) in r.err and str(hooks) in r.err and "left in place" in r.err, r.err
    assert key.read_text() == "ROTATED\n", "restore wrote the old private key back"
    assert (hooks / "pre-commit").read_text() == "#!/bin/sh\nevil\n", "restore wrote outside the repository"
    r = gg.check(repo)
    assert r.blocked and f"ext:{key}" in r.err and f"ext:{hooks}/pre-commit" in r.err, r.err


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


def test_retrust_skips_a_refused_repository(gg: GG, tmp_path: Path) -> None:
    """[59] one repository whose config is refused (hooksPath at its root)
    must not abort `retrust`: `entries()` reports it as `structure`, it is
    skipped and named, the others are re-trusted."""
    m1, m2 = _mk(gg, tmp_path, "m1"), _mk(gg, tmp_path, "m2")
    gg.git("config", "core.hooksPath", ".", cwd=m1)
    r = gg.run("retrust")
    assert r.rc == 0 and f"skipped (structure): {m1}" in r.err, r.text
    assert f"re-trusted: {m2}" in r.out and "1 repository(ies) re-trusted, 1 skipped" in r.out, r.text
    assert gg.check(m1).blocked and not gg.check(m2).blocked


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


@pytest.mark.xfail(strict=True, reason="[44] accepted limitation (DESIGN.md, Known limitations)")
def test_checkout_rewrites_tracked_hook_then_runs_it(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[44] accepted limitation — core.hooksPath in the tree (husky, .githooks) and hooks
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


def _plant_gitlink(gg: GG, r: Path, mark: Path, ref: str = "refs/heads/main",
                   zone: Path | None = None) -> None:
    """The sandbox of [66]: an untracked repository `vendor/x` whose config runs
    a script (core.fsmonitor touching `mark`), a commit whose tree has a
    gitlink at `vendor/x`, and `ref` moved to it — objects and refs are
    volatile, nothing of this is in the fingerprint. For `refs/stash` the
    commit is shaped like a stash (two parents, a reflog entry). With
    `zone`, the planted gitdir is moved there (a volatile zone of a real
    submodule's gitdir, [103]) and `vendor/x/.git` is a gitfile to it."""
    x = r / "vendor/x"
    gg.git("init", "-q", str(x))
    (x / "s").write_text("s\n")
    gg.git("add", "s", cwd=x)
    gg.git("commit", "-qm", "s", cwd=x)
    gitdir = x / ".git"
    if zone is not None:
        import shutil
        zone.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(gitdir), str(zone))
        gitdir = zone
        (x / ".git").write_text(f"gitdir: {os.path.relpath(zone, x)}\n")
    write_exec(gitdir / "fsm.sh", f"#!/bin/sh\ntouch '{mark}'\n")
    gg.git("config", "core.fsmonitor", str(gitdir / "fsm.sh"), cwd=x)
    (x / "s").write_text("dirty\n")        # a dirty submodule tree: what `git status` reports
    sub = gg.git("rev-parse", "HEAD", cwd=x).out.strip()
    import subprocess
    mk = lambda text: subprocess.run(["git", "mktree", "--missing"], cwd=r, env=gg.env, input=text,
                                     capture_output=True, text=True, check=True).stdout.strip()
    vt = mk(f"160000 commit {sub}\tx\n")
    tree = mk(gg.git("ls-tree", "HEAD", cwd=r).out + f"040000 tree {vt}\tvendor\n")
    if ref == "refs/stash":
        idx = gg.git("commit-tree", "-p", "HEAD", "-m", "index", tree, cwd=r).out.strip()
        c = gg.git("commit-tree", "-p", "HEAD", "-p", idx, "-m", "WIP", tree, cwd=r).out.strip()
        gg.git("update-ref", "--create-reflog", "-m", "WIP", ref, c, cwd=r)
    else:
        c = gg.git("commit-tree", "-p", "HEAD", "-m", "evil", tree, cwd=r).out.strip()
        gg.git("update-ref", ref, c, cwd=r)


def _two_branches(gg: GG, tmp_path: Path) -> Path:
    r = tmp_path / "r"
    gg.git("init", "-q", str(r))
    (r / "a").write_text("a\n")
    gg.git("add", "a", cwd=r)
    gg.git("commit", "-qm", "i", cwd=r)
    gg.git("checkout", "-qb", "feature", cwd=r)
    return r


# form: (the user's command, global config, the user has local changes)
GITLINK_BRINGERS = {
    "checkout": (["checkout", "main"], [], False),
    "switch": (["switch", "main"], [], False),
    "alias_global": (["co", "main"], ["alias.co=checkout"], False),
    "alias_quoted": (["co", "main"], ["alias.co='switch' --no-guess"], False),
    "alias_chain": (["c", "main"], ["alias.c=co", "alias.co=checkout"], False),
    "alias_before_global_option": (["--no-pager", "co", "main"], ["alias.co=checkout"], False),
    # [77] other commands that bring the gitlink and enter it
    "merge_autostash": (["merge", "main"], ["merge.autoStash=true"], True),
    "rebase_autostash": (["rebase", "main"], ["rebase.autoStash=true"], True),
    "pull_rebase_autostash": (["pull", ".", "main"], ["pull.rebase=true", "rebase.autoStash=true"], True),
    "pull_merge_autostash": (["pull", "--autostash", "--no-rebase", ".", "main"], [], True),
    "cherry_pick_edit": (["cherry-pick", "-e", "main"], ["core.editor=true"], False),
    # [78] git corrects the word
    "autocorrect_typo": (["chekout", "main"], ["help.autocorrect=immediate"], False),
    "autocorrect_delay": (["swich", "main"], ["help.autocorrect=1"], False),
    # [79] the alias's head is a global option, or a shell alias
    "alias_paginate": (["co", "main"], ["alias.co=-p checkout"], False),
    "alias_config": (["co", "main"], ["alias.co=-c color.ui=auto checkout"], False),
    "alias_config_env": (["co", "main"], ["alias.co=--config-env=core.pager=HOME checkout"], False),
    "alias_shell": (["co", "main"], ["alias.co=!git checkout"], False),
    "alias_shell_dashed": (["co", "main"], ["alias.co=!git-switch"], False),
    "alias_shell_function": (["co", "main"], ['alias.co=!f() { git co2 "$@"; }; f', "alias.co2=switch"],
                             False),
}


def _set_global(gg: GG, r: Path, config: list) -> None:
    for kv in config:
        gg.git("config", "--global", *kv.split("=", 1), cwd=r)


@pytest.mark.parametrize("form", list(GITLINK_BRINGERS))
def test_checkout_brings_a_gitlink_to_a_planted_repository(gg: GG, tmp_path: Path, form: str) -> None:
    """[66] no special config needed. The sandbox plants an untracked nested
    repository `vendor/x` (core.fsmonitor), builds a commit whose tree has a
    gitlink at `vendor/x` and moves `main` to it (objects and refs are
    volatile). The user, on another branch, runs `git checkout main`: the
    index gitguard reads has no gitlink, the check passes; git writes the
    gitlink, then shows the local changes, enters `vendor/x` and runs its
    fsmonitor in the same command. Since DESIGN-exec-path.md: that `git
    status` is a child, gitguard at the exec path, which refuses `vendor/x`
    as never trusted; the command fails there (the gitlink is written,
    the next command is refused), the payload never runs. Formerly a `-c
    diff.ignoreSubmodules=dirty` switch, guessed command by command ([77]
    merge, rebase, pull with an autostash, cherry-pick with the editor;
    [78] a word git autocorrects; [79] an alias whose head is
    `-p`/`-c`/`--config-env`, a shell alias): every form stays as a
    scenario, none needs a rule now. The positive control below runs every
    form with the real git and raw children."""
    mark = tmp_path / "RAN"
    r = _two_branches(gg, tmp_path)
    cmd, config, dirty = GITLINK_BRINGERS[form]
    _set_global(gg, r, config)
    gg.trust(r)
    _plant_gitlink(gg, r, mark)
    assert not mark.exists() and not gg.check(r).blocked
    if dirty:
        (r / "a").write_text("local change\n")   # the autostash needs one
    # the user: the child's refusal reaches the parent's stderr for checkout
    # and switch; merge/rebase/pull silence their autostash's `git status`.
    res = gg.run("git", *cmd, cwd=r)
    assert not mark.exists(), "the planted repository's fsmonitor ran during the command"
    # the command did bring the gitlink, and the next command is refused
    assert gg.git("ls-files", "-s", "vendor/x", cwd=r).out.startswith("160000"), form
    assert gg.check(r).blocked


@pytest.mark.parametrize("form", list(GITLINK_BRINGERS))
def test_gitlink_control_real_git_runs_it(gg: GG, tmp_path: Path, form: str) -> None:
    """[66] [77] [78] [79] positive control of the test above, form by form:
    the real git, same config, same planting, does run the planted
    fsmonitor."""
    mark = tmp_path / "RAN"
    r = _two_branches(gg, tmp_path)
    cmd, config, dirty = GITLINK_BRINGERS[form]
    _set_global(gg, r, config)
    _plant_gitlink(gg, r, mark)
    if dirty:
        (r / "a").write_text("local change\n")
    gg.git(*cmd, cwd=r)
    assert mark.exists(), f"git no longer enters the nested repository with {form}: may be moot"


def test_alias_given_on_the_command_line_is_followed(gg: GG, tmp_path: Path) -> None:
    """[66] `git -c alias.co=checkout co main`: the alias comes from the
    command line (GIT_CONFIG_PARAMETERS), read like the files."""
    mark = tmp_path / "RAN"
    r = _two_branches(gg, tmp_path)
    gg.trust(r)
    _plant_gitlink(gg, r, mark)
    res = gg.run("git", "-c", "alias.co=checkout", "co", "main", cwd=r)
    assert not mark.exists(), res.text


def test_stash_pop_brings_a_gitlink_to_a_planted_repository(gg: GG, tmp_path: Path) -> None:
    """[66] the stash form: a forged `refs/stash` (two parents, a reflog
    entry) whose tree has the gitlink. `git stash pop` applies it, then runs
    `git status`, a child, whose child in `vendor/x` is gitguard: refused."""
    mark = tmp_path / "RAN"
    r = _two_branches(gg, tmp_path)
    gg.trust(r)
    _plant_gitlink(gg, r, mark, ref="refs/stash")
    assert not mark.exists() and not gg.check(r).blocked
    res = gg.run("git", "stash", "pop", cwd=r)
    assert not mark.exists(), "the planted repository's fsmonitor ran during the stash pop"
    assert gg.check(r).blocked


def test_stash_gitlink_control_real_git_runs_it(gg: GG, tmp_path: Path) -> None:
    """[66] positive control of the stash pop test: the real git does run the
    planted fsmonitor."""
    mark = tmp_path / "RAN"
    r = _two_branches(gg, tmp_path)
    _plant_gitlink(gg, r, mark, ref="refs/stash")
    gg.git("stash", "pop", cwd=r)
    assert mark.exists(), "git no longer enters the nested repository: [66] may be moot"


def test_user_ignore_submodules_none_changes_nothing(gg: GG, tmp_path: Path) -> None:
    """[66] no option of the command line reopens the planted repository:
    the child that would enter it is gitguard, whatever `-c` the user
    gives."""
    mark = tmp_path / "RAN"
    r = _two_branches(gg, tmp_path)
    gg.trust(r)
    _plant_gitlink(gg, r, mark)
    res = gg.run("git", "-c", "diff.ignoreSubmodules=none", "checkout", "main", cwd=r)
    assert not mark.exists(), res.text


def test_trust_warns_hooks_in_tree(gg: GG, repo: Path) -> None:
    """[44] accepted limitation made visible: hooks under core.hooksPath in the tree."""
    write_exec(repo / ".githooks/pre-commit", "#!/bin/sh\nexit 0\n")
    gg.git("config", "core.hooksPath", ".githooks", cwd=repo)
    r = gg.run("trust", cwd=repo)
    assert r.rc == 0 and "names in the work tree (.githooks)" in r.err, r.text
    assert "in the work tree" not in gg.run("trust", cwd=gg_plain(gg, repo)).err


def test_trust_warns_include_in_tree_not_submodule_files(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[95] accepted limitation made visible: an include in the tree is
    named; `.gitmodules` and a submodule's gitfile, the tree's own
    structure, are not."""
    from tests.attacks._helpers import add_submodule
    add_submodule(gg, repo, tmp_path)
    r = gg.run("trust", cwd=repo)
    assert r.rc == 0 and "in the work tree" not in r.err, r.text
    (repo / ".gitconfig").write_text("[alias]\n\tst = status\n")
    gg.git("config", "include.path", "../.gitconfig", cwd=repo)
    r = gg.run("trust", cwd=repo)
    assert r.rc == 0 and "names in the work tree (.gitconfig)" in r.err, r.text


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


def test_safe_bare_in_an_included_file(gg: GG, repo: Path) -> None:
    """[85] `safe.bareRepository = explicit` in a file ~/.gitconfig includes:
    git honours it (oracle), the warning must not fire."""
    home = Path(gg.env["HOME"])
    (home / "safe.inc").write_text("[safe]\n\tbareRepository = explicit\n")
    assert gg.git("config", "--global", "include.path", "~/safe.inc").rc == 0
    assert gg.git("config", "safe.bareRepository", cwd=repo).out.strip() == "explicit"
    for r in (gg.run("trust", cwd=repo), gg.run("list"), gg.run("retrust")):
        assert r.rc == 0 and NEEDLE not in r.err, r.text


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
    refs = gg_mod.config_refs(r).refs
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


# ------------------------------- exec-mode carriers [58] [62]
def test_dash_c_fsmonitor_default_expansion_is_refused(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[58] `git -c 'core.fsmonitor=${X:-./p.sh}' status` with p.sh planted
    in the tree: the `-c` value goes through the same tokenizer as the
    files; `-c core.fsmonitor=./p.sh` is refused (control)."""
    mark = tmp_path / "RAN"
    write_exec(repo / "p.sh", f"#!/bin/sh\ntouch '{mark}'\n")
    r = gg.run("git", "-c", "core.fsmonitor=./p.sh", "status", cwd=repo)
    assert r.blocked and not mark.exists(), r.text
    r = gg.run("git", "-c", "core.fsmonitor=${X:-./p.sh}", "status", cwd=repo)
    assert r.blocked and not mark.exists(), r.text


def test_push_to_a_path_in_the_volume_is_checked(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[62] `git push ../other main`: receive-pack runs the destination's
    hooks and honours its config. Watched for a configured local remote
    [45], not for a destination named on the command line."""
    mark = tmp_path / "RAN"
    other = tmp_path / "vol-other.git"
    gg.git("init", "-q", "--bare", str(other))
    write_exec(other / "hooks/pre-receive", f"#!/bin/sh\ntouch '{mark}'\n")
    gg.run("git", "push", "-q", str(other), "main", cwd=repo)
    assert not mark.exists(), "the destination's pre-receive was executed"


@pytest.mark.parametrize("value", ["{root}", "{root}/", "./.", ".git/..", ".", "./"])
def test_hookspath_at_the_root_is_refused_with_the_way_out(gg: GG, repo: Path, value: str) -> None:
    """[59] core.hooksPath resolving to the root of the tree: refused at
    `trust` and on every command, the message names the way out."""
    gg.git("config", "core.hooksPath", value.format(root=repo), cwd=repo)
    for r in (gg.run("trust", cwd=repo), gg.check(repo), gg.run("git", "status", cwd=repo)):
        assert r.blocked and "root of the work tree" in r.err and ".githooks" in r.err, r.text


def test_hookspath_at_the_root_from_the_global_config(gg: GG, repo: Path) -> None:
    """[59] the same from ~/.gitconfig (a repository of global hooks)"""
    gg.git("config", "--global", "core.hooksPath", str(repo))
    r = gg.check(repo)
    assert r.blocked and "root of the work tree" in r.err, r.text


def test_config_naming_the_state_directory_is_refused(gg: GG, repo: Path) -> None:
    """[65] a config path inside gitguard's state directory: refused, the
    reference would watch itself."""
    gg.git("config", "core.hooksPath", str(gg.state), cwd=repo)
    r = gg.run("trust", cwd=repo)
    assert r.blocked and "state directory" in r.err, r.text


# `--repo` only counts without a positional <repository> (git: "the
# command-line argument takes precedence"); push.default=current gives it a
# refspec. `-o` needs a receiving end that advertises push options.
PUSH_FORMS = ["{d} main", "-u {d} main", "--repo {d}", "--repo={d}", "--rep {d}", "--rep={d}",
              "-o x {d} main", "-qo x {d} main", "-ox {d} main", "--push-option x {d} main",
              "--push x {d} main", "--push-option=x {d} main",
              "--receive-pack git-receive-pack {d} main", "-f -- {d} main", "file://{d} main",
              "../vol-other.git main", "--force-with-lease {d} main", "--no-repo {d} main",
              "--repo origin {d} main"]


@pytest.mark.parametrize("form", PUSH_FORMS)
def test_push_destination_forms_are_read(gg: GG, repo: Path, tmp_path: Path, form: str) -> None:
    """[62] every way of naming the destination on the command line, the
    abbreviated options parse-options accepts included: refused, and the
    destination's hook does not run. Control: the real git does run it."""
    mark = tmp_path / "RAN"
    other = tmp_path / "vol-other.git"
    gg.git("init", "-q", "--bare", str(other))
    gg.git("config", "receive.advertisePushOptions", "true", cwd=other)
    gg.git("config", "--global", "push.default", "current")
    write_exec(other / "hooks/pre-receive", f"#!/bin/sh\ntouch '{mark}'\n")
    args = form.format(d=other).split()
    r = gg.run("git", "push", "-q", *args, cwd=repo)
    assert r.blocked and "[62]" in r.err and not mark.exists(), r.text
    gg.git("push", "-q", *args, cwd=repo)
    assert mark.exists(), "control: git runs the destination's pre-receive"


def test_push_to_self_and_to_a_configured_remote_path(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[62] allowed: `git push . main:x` (the repository itself), and the
    path of a configured — hence watched — local remote."""
    assert gg.run("git", "push", "-q", ".", "main:x", cwd=repo).rc == 0
    other = tmp_path / "vol-other.git"
    gg.git("init", "-q", "--bare", str(other))
    gg.git("remote", "add", "origin", str(other), cwd=repo)
    gg.trust(repo)
    r = gg.run("git", "push", "-q", str(other), "main", cwd=repo)
    assert r.rc == 0, r.text
    r = gg.run("git", "push", "-q", "origin", "main:y", cwd=repo)
    assert r.rc == 0, r.text


def test_push_to_a_name_only_a_submodule_configures(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[62] `git push foo` where only a submodule's config defines remote
    `foo`: for the superproject's git, `foo` is a path (here a repository
    in the tree). Refused: a submodule's remotes are not the repository's."""
    from tests.attacks._helpers import add_submodule
    mark = tmp_path / "RAN"
    sub = add_submodule(gg, repo, tmp_path)
    gg.git("init", "-q", "--bare", str(repo / "foo"))
    write_exec(repo / "foo/hooks/pre-receive", f"#!/bin/sh\ntouch '{mark}'\n")
    gg.git("remote", "add", "foo", str(tmp_path / "elsewhere.git"), cwd=sub)
    gg.trust(repo)
    r = gg.run("git", "push", "-q", "foo", "main", cwd=repo)
    assert r.blocked and "[62]" in r.err and not mark.exists(), r.text
    gg.git("push", "-q", "foo", "main", cwd=repo)
    assert mark.exists(), "control: git takes `foo` as a path and runs its pre-receive"


# ---------------------------------------- adversarial review of 2026-10-22
def test_push_to_a_percent_encoded_file_url_is_checked(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[69] `git push file://…/My%20Repos/other.git` to an
    unconfigured repository: git decodes the URL and runs its hooks, the
    [62] check found no repository at the encoded path."""
    mark = tmp_path / "RAN"
    other = tmp_path / "My Repos/other.git"
    gg.git("init", "-q", "--bare", str(other))
    write_exec(other / "hooks/pre-receive", f"#!/bin/sh\ntouch '{mark}'\n")
    gg.run("git", "push", "-q", "file://" + str(other).replace(" ", "%20"), "main", cwd=repo)
    assert not mark.exists(), "the destination's pre-receive ran"


def test_in_tree_symlink_spelled_through_an_alias_is_refused(gg: GG, repo: Path,
                                                            tmp_path: Path) -> None:
    """[75] the symlink rule follows the link's location, not its spelling:
    `core.hooksPath = <alias>/.githooks`, <alias> a symlink to the tree and
    `.githooks` a symlink in the tree to a directory elsewhere, is refused
    like `core.hooksPath = .githooks` is; only a link outside the tree is
    ordinary."""
    elsewhere = tmp_path / "elsewhere"
    write_exec(elsewhere / "pre-commit", "#!/bin/sh\nexit 0\n")
    (repo / ".githooks").symlink_to(elsewhere)
    alias = tmp_path / "alias"
    alias.symlink_to(repo)
    gg.git("config", "core.hooksPath", str(alias / ".githooks"), cwd=repo)
    r = gg.run("trust", cwd=repo)
    assert r.rc != 0 and "symlink" in r.err, r.text
    gg.git("config", "core.hooksPath", ".githooks", cwd=repo)
    r = gg.run("trust", cwd=repo)
    assert r.rc != 0 and "symlink" in r.err, r.text


def _archive_sibling(gg: GG, tmp_path: Path) -> Path:
    """A repository next to `repo` whose tar.tgz.command touches RAN."""
    sib = tmp_path / "sib"
    gg.git("init", "-q", str(sib))
    (sib / "a").write_text("a\n")
    gg.git("add", "a", cwd=sib)
    gg.git("commit", "-qm", "a", cwd=sib)
    gg.git("config", "tar.tgz.command", f"touch '{tmp_path / 'RAN'}'; gzip -cn", cwd=sib)
    return sib


def test_archive_remote_to_a_path_is_checked(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[70] `git archive --remote=../sib --format=tgz`: upload-archive
    runs in the sibling repository and executes its `tar.tgz.command`
    (remote-enabled by default for tgz/tar.gz). Only `push` was checked."""
    mark = tmp_path / "RAN"
    _archive_sibling(gg, tmp_path)
    r = gg.run("git", "archive", "--remote=../sib", "--format=tgz", "-o", os.devnull, "HEAD", cwd=repo)
    assert r.blocked and "[70]" in r.err and not mark.exists(), r.text
    gg.git("archive", "--remote=../sib", "--format=tgz", "-o", os.devnull, "HEAD", cwd=repo)
    assert mark.exists(), "control: git runs it"


def test_archive_remote_outside_any_repository_is_checked(gg: GG, tmp_path: Path) -> None:
    """[81] the same `git archive --remote=../sib` from a directory that is
    no repository: gitguard found no root and ran git unchecked, and git
    still started upload-archive in `sib`, which ran its tar.tgz.command."""
    mark = tmp_path / "RAN"
    _archive_sibling(gg, tmp_path)
    out = tmp_path / "elsewhere"
    out.mkdir()
    r = gg.run("git", "archive", "--remote=../sib", "--format=tgz", "-o", os.devnull, "HEAD", cwd=out)
    assert r.blocked and "[81]" in r.err and "git -C ../sib archive" in r.err and not mark.exists(), r.text
    r = gg.run("git", "-C", str(out), "archive", "--remote", "../sib", "--format=tgz", "-o",
               os.devnull, "HEAD", cwd=tmp_path)
    assert r.blocked and "[81]" in r.err and not mark.exists(), r.text
    gg.git("archive", "--remote=../sib", "--format=tgz", "-o", os.devnull, "HEAD", cwd=out)
    assert mark.exists(), "control: git runs it"


def test_archive_outside_any_repository_allowed_cases(gg: GG, tmp_path: Path) -> None:
    """[81] outside a repository, a destination that is no local repository
    and a plain command are git's business: no refusal from gitguard."""
    out = tmp_path / "elsewhere"
    out.mkdir()
    r = gg.run("git", "archive", "--remote=../nothing-here", "--format=tar", "HEAD", cwd=out)
    assert "[81]" not in r.err and "gitguard" not in r.err, r.text
    r = gg.run("git", "--version", cwd=out)
    assert r.rc == 0, r.text


def test_push_to_a_remote_section_without_url_is_checked(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[82] a `[remote "origin"]` section without a url (a global
    `remote.origin.prune = true`) made `origin` a configured remote for
    gitguard; git, finding no url, takes `origin` as a path: `<root>/origin`,
    a bare repository the sandbox planted, whose pre-receive ran."""
    mark = tmp_path / "RAN"
    gg.git("config", "--global", "remote.origin.prune", "true")
    gg.trust(repo)
    hub = repo / "origin"
    gg.git("init", "-q", "--bare", str(hub))
    write_exec(hub / "hooks/pre-receive", f"#!/bin/sh\ntouch '{mark}'\n")
    r = gg.run("git", "push", "-q", "origin", "main", cwd=repo)
    assert r.blocked and "[62]" in r.err and not mark.exists(), r.text
    gg.git("push", "-q", "origin", "main", cwd=repo)
    assert mark.exists(), "control: git pushes to the path"


def test_push_to_a_remote_with_url_stays_allowed(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[82] control: a remote whose url the trusted config gives is still a
    remote — its config and hooks are watched ([45]), the push is not refused."""
    hub = tmp_path / "vol-hub.git"
    gg.git("init", "-q", "--bare", str(hub))
    gg.git("remote", "add", "origin", str(hub), cwd=repo)
    gg.git("config", "remote.origin.prune", "true", cwd=repo)
    gg.trust(repo)
    r = gg.run("git", "push", "-q", "origin", "main", cwd=repo)
    assert r.rc == 0 and not r.blocked, r.text


def test_fsck_lost_found_writes_through_a_planted_symlink(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[83] positive control for keeping lost-found/ watched: with the real
    git, `fsck --lost-found` writes a dangling blob's content through a
    symlink planted at lost-found/other/<sha> — here onto post-commit, which
    the next commit runs."""
    import subprocess
    mark = tmp_path / "RAN"
    write_exec(repo / ".git/hooks/post-commit", "#!/bin/sh\nexit 0\n")
    sha = subprocess.run(["git", "hash-object", "-w", "--stdin"], cwd=repo, env=gg.env,
                         input=f"#!/bin/sh\ntouch '{mark}'\n", capture_output=True, text=True,
                         check=True).stdout.strip()
    (repo / ".git/lost-found/other").mkdir(parents=True)
    (repo / ".git/lost-found/other" / sha).symlink_to("../../hooks/post-commit")
    assert gg.check(repo).blocked, "the planted link must be a new entry"
    gg.git("fsck", "--lost-found", cwd=repo)
    gg.git("commit", "-q", "--allow-empty", "-m", "x", cwd=repo)
    assert mark.exists(), "git no longer writes through the link: lost-found could become volatile"


# How cmd_archive takes --remote (PARSE_OPT_KEEP_ALL), checked on git 2.47
# and 2.50: each form below reaches ../sib with plain git.
ARCHIVE_FORMS = {
    "separate": ["--remote", "../sib", "--format=tgz", "HEAD"],
    "after_positional": ["--format=tgz", "HEAD", "--remote=../sib"],
    "last_wins": ["--remote=/nonexistent", "--remote=../sib", "--format=tgz", "HEAD"],
    "after_attached_output": ["-o" + os.devnull, "--remote=../sib", "--format=tgz", "HEAD"],
    "after_long_output": ["--output", os.devnull, "--remote=../sib", "--format=tgz", "HEAD"],
    "after_unknown_cluster": ["-9o", os.devnull, "--remote=../sib", "--format=tgz", "HEAD"],
    "file_url": ["--remote=file://{sib}", "--format=tgz", "HEAD"],
}


@pytest.mark.parametrize("form", sorted(ARCHIVE_FORMS))
def test_archive_remote_forms_are_checked(gg: GG, repo: Path, tmp_path: Path, form: str) -> None:
    """[70] every spelling of --remote git honours is seen"""
    mark = tmp_path / "RAN"
    sib = _archive_sibling(gg, tmp_path)
    args = [a.replace("{sib}", str(sib)) for a in ARCHIVE_FORMS[form]]
    r = gg.run("git", "archive", *args, cwd=repo)
    assert r.blocked and "[70]" in r.err and not mark.exists(), r.text
    c = gg.git("archive", *args, cwd=repo)
    # `-9o` reaches ../sib, whose upload-archive then dies on the kept `-9o`.
    reached = mark.exists() or (form == "after_unknown_cluster" and "remote:" in c.err)
    assert reached, f"control: git did not reach ../sib\n{c.text}"


def test_archive_remote_from_a_subdirectory_is_relative_to_the_root(gg: GG, repo: Path,
                                                                     tmp_path: Path) -> None:
    """[70] git resolves --remote from the top of the tree, like push"""
    _archive_sibling(gg, tmp_path)
    (repo / "src").mkdir()
    r = gg.run("git", "archive", "--remote=../sib", "--format=tgz", "-o", os.devnull, "HEAD",
               cwd=repo / "src")
    assert r.blocked and "[70]" in r.err, r.text


def test_archive_remote_allowed_cases(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[70] a configured remote (its config watched), `--no-remote`, and
    `--remote` as the value of `--exec` or after `--` are not refused"""
    mark = tmp_path / "RAN"
    _archive_sibling(gg, tmp_path)
    for args in (["--remote=../sib", "--no-remote"], ["--exec", "--remote=../sib"],
                 ["--", "--remote=../sib"]):
        r = gg.run("git", "archive", "--format=tgz", "-o", os.devnull, *args, cwd=repo)
        assert "[70]" not in r.err, (args, r.text)
    gg.git("remote", "add", "sib", "../sib", cwd=repo)
    gg.trust(repo)
    r = gg.run("git", "archive", "--remote=sib", "--format=tgz", "-o", os.devnull, "HEAD", cwd=repo)
    assert not r.blocked and mark.exists(), r.text


# `--work-tree` without `--git-dir`: discovery from the cwd, the given tree
# used; a relative one from the final cwd (after -C); the environment wins
# over core.worktree. Each form reaches ../w with plain git (control below).
WORK_TREE_FORMS = {
    "relative": (["--work-tree=../w"], "repo", {}),
    "absolute": (["--work-tree={w}"], "repo", {}),
    "separate": (["--work-tree", "../w"], "repo", {}),
    "after_C": (["-C", "src", "--work-tree=../../w"], "repo", {}),
    "env": ([], "repo", {"GIT_WORK_TREE": "{w}"}),
    "env_over_core_worktree": ([], "repo", {"GIT_WORK_TREE": "{w}", "CORE_WORKTREE": "{w2}"}),
}


@pytest.mark.parametrize("form", sorted(WORK_TREE_FORMS))
def test_work_tree_alone_checks_the_given_tree(gg: GG, repo: Path, tmp_path: Path,
                                               form: str) -> None:
    """[72] `git --work-tree=../w commit` (no --git-dir): git discovers the
    gitdir from the cwd and takes ../w as the work tree, where it resolves a
    relative core.hooksPath; gitguard checked the discovered tree. ([18]
    fixed the opposite: discovery from the cwd, not from ../w.) The tree
    given is trusted (same state key: the directory holding .git), its
    hook rewritten, the commit refused; untouched, it runs (control)."""
    import subprocess
    from tests.conftest import GITGUARD
    args, _, env_add = WORK_TREE_FORMS[form]
    w, w2 = tmp_path / "w", tmp_path / "w2"
    sub = lambda a: a.replace("{w}", str(w)).replace("{w2}", str(w2))
    args = [sub(a) for a in args]
    env = dict(gg.env, **{k: sub(v) for k, v in env_add.items() if k != "CORE_WORKTREE"})
    if "CORE_WORKTREE" in env_add:
        (w2 / ".githooks").mkdir(parents=True)
        gg.git("config", "core.worktree", str(w2), cwd=repo)
    mark = tmp_path / "RAN"
    (repo / "src").mkdir()
    gg.git("config", "core.hooksPath", ".githooks", cwd=repo)
    write_exec(w / ".githooks/pre-commit", f"#!/bin/sh\ntouch '{mark}'\n")
    run = lambda *a, e=env: subprocess.run([sys.executable, str(GITGUARD), *a], cwd=repo, env=e,
                                           capture_output=True, text=True)
    # trust takes no git option: the tree is given through the environment,
    # the same root the command's --work-tree designates (same state key:
    # the directory holding .git; trusting the repository's own tree would
    # leave ../w's hooks "added", and the command refused).
    assert run("trust", e=dict(env, GIT_WORK_TREE=str(w))).returncode == 0
    r = run("git", *args, "commit", "-q", "--allow-empty", "-m", "x")
    assert r.returncode == 0 and mark.exists(), f"control: the trusted hook of ../w runs\n{r.stderr}"
    mark.unlink()
    write_exec(w / ".githooks/pre-commit", f"#!/bin/sh\ntouch '{mark}'; echo evil\n")
    r = run("git", *args, "commit", "-q", "--allow-empty", "-m", "y")
    assert r.returncode != 0 and not mark.exists(), f"the rewritten hook of ../w ran\n{r.stderr}"
    assert ".githooks/pre-commit" in r.stderr, r.stderr


def test_work_tree_alone_to_a_missing_directory_is_refused(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[72] fail closed: a work tree that does not exist is refused, not
    checked as the discovered tree."""
    gg.trust(repo)
    r = gg.run("git", f"--work-tree={tmp_path}/nope", "status", cwd=repo)
    assert r.blocked and "GIT_WORK_TREE" in r.err, r.text


# ------------------------------- adversarial review of 2026-10-24 (second pass)
# Findings [86]–[99] (adversarial review of 2026-10-24, second pass): each
# test of gitguard has a positive control that runs the same planting with
# the real git and must pass (if git stops doing it, the test may be moot).
# The attacks refused at the check live in tests/attacks/ ([87] [88]
# [90]–[94] [96]); their controls are here, calling the attack function
# itself (its payload touches tmp_path/RAN). [89] closed by the exec-path
# design (the `git diff` in the planted repository is a child, gitguard);
# [95] [123] accepted: same repository, same command (DESIGN.md, Known limitations).
from tests.attacks import config_scope as _cs, nested as _nested, symlinks as _links  # noqa: E402
from tests.attacks._helpers import git_has  # noqa: E402
from tests.conftest import GITGUARD  # noqa: E402

EDITOR = "sh -c 'echo msg > \"$1\"' x"      # the user writes a message


def _nested_repo(gg: GG, d: Path, mark: Path) -> None:
    """A repository at `d` whose core.fsmonitor touches `mark`."""
    assert gg.git("init", "-q", str(d)).rc == 0
    (d / "s").write_text("s\n")
    gg.git("add", "s", cwd=d)
    gg.git("commit", "-qm", "s", cwd=d)
    write_exec(d / ".git/fsm.sh", f"#!/bin/sh\ntouch '{mark}'\n")
    gg.git("config", "core.fsmonitor", str(d / ".git/fsm.sh"), cwd=d)


def _typechange_to_repo(gg: GG, repo: Path, mark: Path) -> None:
    """[86] The sandbox replaces the tracked file `f` by a repository (no
    gitlink in the index yet: the check passes) and edits another file, so
    the user has something to commit."""
    (repo / "g").write_text("g\n")
    gg.git("add", "g", cwd=repo)
    gg.git("commit", "-qm", "g", cwd=repo)
    gg.trust(repo)
    (repo / "f").unlink()
    _nested_repo(gg, repo / "f", mark)
    (repo / "g").write_text("g2\n")


# commit forms that stage the typechange, then render the message template
# (or the --dry-run/-v status): git enters the new gitlink. `-m` renders none.
COMMIT_TYPECHANGE = {
    "all": ["commit", "-a"],
    "all_verbose": ["commit", "-a", "-v"],
    "all_dry_run": ["commit", "-a", "--dry-run"],
    "pathspec": ["commit", "f", "g"],
    "include": ["commit", "-i", "f"],
}


@pytest.mark.parametrize("form", list(COMMIT_TYPECHANGE))
def test_commit_stages_a_typechange_to_a_planted_repository(gg: GG, repo: Path, tmp_path: Path,
                                                            form: str) -> None:
    """[86] `commit` was exempt from the former switch on the ground that it
    never writes a gitlink from a tree; `commit -a` (or a pathspec) does,
    when the sandbox replaced a tracked file by a repository: the typechange
    100644 → 160000 is staged, then the message template's status entered
    it and ran its fsmonitor, in the command whose check passed. That
    status is a child git: gitguard, which refuses `vendor/x`."""
    mark = tmp_path / "RAN"
    _typechange_to_repo(gg, repo, mark)
    assert not mark.exists() and not gg.check(repo).blocked
    gg.env["GIT_EDITOR"] = EDITOR
    gg.run("git", *COMMIT_TYPECHANGE[form], cwd=repo)
    assert not mark.exists(), "the planted repository's fsmonitor ran during the commit"


@pytest.mark.parametrize("form", list(COMMIT_TYPECHANGE))
def test_commit_typechange_control_real_git_runs_it(gg: GG, repo: Path, tmp_path: Path,
                                                    form: str) -> None:
    """[86] positive control: the real git runs the planted fsmonitor."""
    mark = tmp_path / "RAN"
    _typechange_to_repo(gg, repo, mark)
    gg.env["GIT_EDITOR"] = EDITOR
    gg.git(*COMMIT_TYPECHANGE[form], cwd=repo)
    assert mark.exists(), f"git no longer enters the typechanged repository with {form}: may be moot"


# partial commits build a temporary index from HEAD: a gitlink the sandbox
# committed (objects, refs: volatile) is in it, and the template enters it.
COMMIT_FROM_HEAD = {
    "pathspec": ["commit", "a"],
    "only": ["commit", "-o", "a"],
    "verbose": ["commit", "-v", "a"],
    "dry_run": ["commit", "--dry-run", "a"],
    "amend": ["commit", "--amend", "a"],
}


def _gitlink_in_head(gg: GG, tmp_path: Path, mark: Path) -> Path:
    r = _two_branches(gg, tmp_path)
    gg.trust(r)
    _plant_gitlink(gg, r, mark, ref="refs/heads/feature")     # the branch the user is on
    (r / "a").write_text("b\n")
    return r


def _gitlink_in_head_volatile_zone(gg: GG, tmp_path: Path, mark: Path) -> Path:
    """[103] as _gitlink_in_head, the planted gitdir sitting in a volatile
    zone of a real submodule's gitdir (`.git/modules/sub/refs/p`), hashed
    by nobody; the marker covered it by prefix, the child inherited."""
    from tests.attacks._helpers import add_submodule
    r = _two_branches(gg, tmp_path)
    add_submodule(gg, r, tmp_path)
    gg.trust(r)
    _plant_gitlink(gg, r, mark, ref="refs/heads/feature", zone=r / ".git/modules/sub/refs/p")
    (r / "a").write_text("b\n")
    return r


@pytest.mark.parametrize("form", list(COMMIT_FROM_HEAD))
def test_partial_commit_enters_a_gitlink_from_head(gg: GG, tmp_path: Path, form: str) -> None:
    """[86] the sandbox moves the current branch to a commit with a
    gitlink `vendor/x` on its planted repository; the index has none, the
    check passes. `git commit a` resets a temporary index from HEAD,
    gitlink included, and its message template ran `git status` in
    `vendor/x`; with the switch it does not."""
    mark = tmp_path / "RAN"
    r = _gitlink_in_head(gg, tmp_path, mark)
    assert not mark.exists() and not gg.check(r).blocked
    gg.env["GIT_EDITOR"] = EDITOR
    gg.run("git", *COMMIT_FROM_HEAD[form], cwd=r)
    assert not mark.exists(), "the planted repository's fsmonitor ran during the commit"


@pytest.mark.parametrize("form", list(COMMIT_FROM_HEAD))
def test_partial_commit_control_real_git_runs_it(gg: GG, tmp_path: Path, form: str) -> None:
    """[86] positive control: the real git runs the planted fsmonitor."""
    mark = tmp_path / "RAN"
    r = _gitlink_in_head(gg, tmp_path, mark)
    gg.env["GIT_EDITOR"] = EDITOR
    gg.git(*COMMIT_FROM_HEAD[form], cwd=r)
    assert mark.exists(), f"git no longer enters the gitlink from HEAD with {form}: may be moot"


# (the user's command, global config): git shows the submodule's content by
# running `git diff` inside it, which `diff.ignoreSubmodules=dirty` does not stop.
SUBMODULE_DIFF = {
    "show_global": (["show", "main"], ["diff.submodule=diff"]),
    "log_p_global": (["log", "-p", "-1", "main"], ["diff.submodule=diff"]),
    "diff_revs_global": (["diff", "feature", "main"], ["diff.submodule=diff"]),
    "show_flag": (["show", "--submodule=diff", "main"], []),
    "log_p_flag": (["log", "-p", "--submodule=diff", "-1", "main"], []),
}


def _gitlink_with_diff_driver(gg: GG, tmp_path: Path, mark: Path, config: list) -> Path:
    r = _two_branches(gg, tmp_path)
    _set_global(gg, r, config)
    gg.trust(r)
    _plant_gitlink(gg, r, mark)
    x = r / "vendor/x"
    write_exec(x / ".git/ext.sh", f"#!/bin/sh\ntouch '{mark}'\n")
    gg.git("config", "diff.external", str(x / ".git/ext.sh"), cwd=x)
    return r


@pytest.mark.parametrize("form", list(SUBMODULE_DIFF))
def test_submodule_content_diff_enters_a_planted_repository(gg: GG, tmp_path: Path, form: str) -> None:
    """[89] the planting of [66], the nested repository's diff.external as
    payload. With `diff.submodule = diff` (global) or `--submodule=diff`,
    show/log -p/diff of the sandbox's commit run `git diff` inside
    `vendor/x`, honouring its config. An accepted limitation under the
    former switch (which only dropped the dirty-tree probe); closed by the
    exec-path design: that `git diff` is a child, gitguard, refused."""
    mark = tmp_path / "RAN"
    cmd, config = SUBMODULE_DIFF[form]
    r = _gitlink_with_diff_driver(gg, tmp_path, mark, config)
    assert not mark.exists() and not gg.check(r).blocked
    gg.run("git", *cmd, cwd=r)
    assert not mark.exists(), "the planted repository's diff driver ran"


@pytest.mark.parametrize("form", list(SUBMODULE_DIFF))
def test_submodule_content_diff_control_real_git_runs_it(gg: GG, tmp_path: Path, form: str) -> None:
    """[89] positive control: the real git with raw children runs the
    planted diff driver."""
    mark = tmp_path / "RAN"
    cmd, config = SUBMODULE_DIFF[form]
    r = _gitlink_with_diff_driver(gg, tmp_path, mark, config)
    gg.git(*cmd, cwd=r)
    assert mark.exists(), f"git no longer diffs inside the submodule with {form}: may be moot"


def _on_tty(argv: list[str], env: dict, cwd: Path) -> bytes:
    """Run `argv` with stdin, stdout and stderr on a pseudo-terminal (the
    user typing the command): git starts its pager only on a terminal."""
    import pty
    import select
    import subprocess
    import time
    master, slave = pty.openpty()
    p = subprocess.Popen(argv, cwd=cwd, env=env, stdin=slave, stdout=slave, stderr=slave,
                         close_fds=True)
    os.close(slave)
    out, deadline = b"", time.monotonic() + 30
    while time.monotonic() < deadline:
        ready, _, _ = select.select([master], [], [], 0.2)
        if ready:
            try:
                chunk = os.read(master, 4096)
            except OSError:
                break
            if not chunk:
                break
            out += chunk
        elif p.poll() is not None:
            break
    p.wait(timeout=30)
    os.close(master)
    return out


def _tracked_include_branch(gg: GG, tmp_path: Path, mark: Path, absent: bool = False) -> Path:
    """[95] The user: a tracked project config `.gitconfig`, included from
    `.git/config` (`include.path = ../.gitconfig`), trusted. The sandbox:
    objects and a ref only — a branch `agent` whose `.gitconfig` sets
    `pager.maintenance`. [123] `absent`: the include names a file that does
    not exist at trust (an optional local config), which nothing watches."""
    r = tmp_path / "r"
    gg.git("init", "-q", str(r))
    (r / ("README" if absent else ".gitconfig")).write_text("[alias]\n\tst = status\n")
    gg.git("add", "-A", cwd=r)
    gg.git("commit", "-qm", "init", cwd=r)
    gg.git("config", "include.path", "../.gitconfig", cwd=r)
    gg.trust(r)
    import subprocess
    run = lambda text, *a: subprocess.run(["git", *a], cwd=r, env=gg.env, input=text,
                                          capture_output=True, text=True, check=True).stdout.strip()
    blob = run(f"[pager]\n\tmaintenance = touch '{mark}'; cat\n", "hash-object", "-w", "--stdin")
    tree = run(f"100644 blob {blob}\t.gitconfig\n", "mktree")
    c = run("", "commit-tree", "-p", "HEAD", "-m", "agent work", tree)
    gg.git("update-ref", "refs/heads/agent", c, cwd=r)
    return r


@pytest.mark.parametrize("absent", [False, True])
@pytest.mark.xfail(strict=True, reason="[95] [123] accepted limitation (DESIGN.md, Known limitations)")
def test_merge_checks_out_a_tracked_include_then_reads_it(gg: GG, tmp_path: Path, absent: bool) -> None:
    """[95] Variant of [44] for config: a tracked file the trusted config
    includes. Nothing in the fingerprint changes (objects, refs); `git merge
    --ff-only agent` checks the new `.gitconfig` out, then spawns `git
    maintenance run --auto`, which reads it and starts its "pager" on the
    user's terminal. With gitguard at the exec path that child is gitguard,
    but it is the same repository and the same command: it inherits the
    parent's judgment, by design — a child that re-judged the tree there
    broke ordinary commands and lost uncommitted work ([124]). `trust`
    names the file. [123] The same with an include absent at trust."""
    mark = tmp_path / "RAN"
    r = _tracked_include_branch(gg, tmp_path, mark, absent)
    assert not gg.check(r).blocked
    _on_tty([sys.executable, str(GITGUARD), "git", "merge", "-q", "--ff-only", "agent"], gg.env, r)
    assert not mark.exists(), "pager.maintenance from the sandbox's branch ran during the merge"


@pytest.mark.parametrize("absent", [False, True])
def test_tracked_include_control_real_git_runs_it(gg: GG, tmp_path: Path, absent: bool) -> None:
    """[95] [123] positive control: the real git, on a terminal, runs it."""
    mark = tmp_path / "RAN"
    r = _tracked_include_branch(gg, tmp_path, mark, absent)
    _on_tty(["git", "merge", "-q", "--ff-only", "agent"], gg.raw_env, r)
    assert mark.exists(), "the merge no longer reads the checked-out include: [95] may be moot"


def _gitdir_at_root(repo: Path, mark: Path) -> None:
    """[97] The sandbox lays a gitdir out in the root of the tree (untracked
    files): HEAD, objects/, refs/, a config with an alias."""
    (repo / "HEAD").write_text("ref: refs/heads/main\n")
    (repo / "objects").mkdir()
    (repo / "refs").mkdir()
    (repo / "config").write_text(f"[core]\n\tbare = true\n[alias]\n\tlg = !touch '{mark}'\n")


def test_bare_option_opens_the_cwd_as_gitdir(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[97] `git --bare <cmd>` makes git take the cwd as its gitdir
    (handle_options sets GIT_DIR); gitguard took `--bare` for an inert flag,
    found the repository from the cwd and checked its trusted `.git`."""
    mark = tmp_path / "RAN"
    _gitdir_at_root(repo, mark)
    assert not gg.check(repo).blocked
    gg.run("git", "--bare", "lg", cwd=repo)
    assert not mark.exists(), "git ran the config of the gitdir planted in the tree"


def test_bare_option_control_real_git_runs_it(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[97] positive control."""
    mark = tmp_path / "RAN"
    _gitdir_at_root(repo, mark)
    gg.git("--bare", "lg", cwd=repo)
    assert mark.exists(), "git --bare no longer opens the cwd: [97] may be moot"


TEMPLATE_ABBREVS = ["--templ", "--templa", "--templat"]


def _new_repo_with_template(gg: GG, tmp_path: Path, cmd: str, opt: str) -> list[str]:
    tpl = _tpl(tmp_path)
    src = [str(make_source(gg, tmp_path))] if cmd == "clone" else []
    return [cmd, "-q", f"{opt}={tpl}", *src, "c"]


@pytest.mark.parametrize("opt", TEMPLATE_ABBREVS)
@pytest.mark.parametrize("cmd", ["init", "clone"])
def test_template_option_abbreviated_no_autotrust(gg: GG, tmp_path: Path, cmd: str, opt: str) -> None:
    """[98] git's parse-options accepts any unique prefix of a long
    option: `--templ=<dir>` copies the template's hooks, but parse_new_repo
    recognised `--template` only, and auto-trusted the new repository with
    them ([42])."""
    res = gg.run("git", *_new_repo_with_template(gg, tmp_path, cmd, opt), cwd=tmp_path)
    assert res.rc == 0, res.text
    assert gg.check(tmp_path / "c").blocked


@pytest.mark.parametrize("opt", TEMPLATE_ABBREVS)
@pytest.mark.parametrize("cmd", ["init", "clone"])
def test_template_option_abbreviated_control(gg: GG, tmp_path: Path, cmd: str, opt: str) -> None:
    """[98] positive control: the real git takes the abbreviation for
    `--template` and copies the hook."""
    assert gg.git(*_new_repo_with_template(gg, tmp_path, cmd, opt), cwd=tmp_path).rc == 0
    assert (tmp_path / "c/.git/hooks/post-checkout").exists()


def _fifo_at(repo: Path, rel: str) -> None:
    p = repo / rel
    if p.exists():
        p.unlink()
    os.mkfifo(p)


def _fifo_include(repo: Path, rel: str) -> None:
    os.mkfifo(repo / ".git/team.inc")
    with open(repo / ".git/config", "a") as f:
        f.write("[include]\n\tpath = team.inc\n")


def _symlink_to_fifo(repo: Path, rel: str) -> None:
    os.mkfifo(repo.parent / "fifo")
    (repo / rel).unlink()
    os.symlink(repo.parent / "fifo", repo / rel)


FIFO_PLANTINGS = {
    "config": (_fifo_at, ".git/config"),
    "index": (_fifo_at, ".git/index"),
    "HEAD": (_fifo_at, ".git/HEAD"),
    "include": (_fifo_include, ""),
    "symlink_config": (_symlink_to_fifo, ".git/config"),
}


@pytest.mark.parametrize("where", list(FIFO_PLANTINGS))
def test_fifo_is_refused_not_waited_on(gg: GG, repo: Path, where: str) -> None:
    """[99] a FIFO in place of a file git reads (`.git/config`, the index,
    HEAD, an included file, or a symlink to a FIFO): the reader blocked in
    open() for ever. Fail closed (git never ran) but a denial of service
    that pushes the user toward the real git. Refused at once now, with the
    file named (or, for HEAD, no repository: git finds none either)."""
    import subprocess
    plant, rel = FIFO_PLANTINGS[where]
    plant(repo, rel)
    r = subprocess.run([sys.executable, str(GITGUARD)], cwd=repo, env=gg.env,
                       capture_output=True, text=True, timeout=5)
    assert r.returncode != 0, r.stdout + r.stderr
    if where != "HEAD":
        assert "not a regular file" in r.stderr, r.stderr


def test_dev_null_global_config_is_read_as_empty(gg: GG, repo: Path) -> None:
    """[99] the one device git reads like a file: GIT_CONFIG_GLOBAL=/dev/null
    (a common idiom) still reads empty, not refused."""
    gg.env["GIT_CONFIG_GLOBAL"] = os.devnull
    r = gg.run("git", "status", cwd=repo)
    assert r.rc == 0 and "On branch" in r.out, r.text


# ----------------------- positive controls of the attacks [87] [88] [90]–[94] [96]
def test_sparse_index_control_real_git_runs_it(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[87] the sparse index hides the gitlink from gitguard's parser, not
    from git: `git status` expands it and runs the planted fsmonitor."""
    from gitguard import index_gitlinks
    _nested.attack_sparse_index_hides_gitlink(gg, repo, tmp_path)
    assert index_gitlinks(repo / ".git/index") == []
    gg.git("status", cwd=repo)
    assert (tmp_path / "RAN").exists(), "git no longer expands the sparse entry: [87] may be moot"


def test_hardlink_hook_control_real_git_runs_it(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[88] `git commit --amend --no-edit` writes the sandbox's message into
    the hook's inode and runs it."""
    _links.attack_hardlink_commit_editmsg_to_hook(gg, repo, tmp_path)
    gg.git("commit", "-q", "--amend", "--no-edit", cwd=repo)
    assert (tmp_path / "RAN").exists(), "git no longer writes COMMIT_EDITMSG in place: [88] may be moot"


def test_hardlink_tree_hook_control_real_git_runs_it(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[88] the same with the hook in the tree."""
    _links.attack_hardlink_commit_editmsg_to_tree_hook(gg, repo, tmp_path)
    gg.git("commit", "-q", "--amend", "--no-edit", cwd=repo)
    assert (tmp_path / "RAN").exists()


def test_hardlink_is_what_runs_the_message(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[88] counter-control: the same commit without the link — git does not
    execute a commit message."""
    from tests.attacks._helpers import hardlink_editmsg_to_hook, payload
    hook = repo / ".git/hooks/commit-msg"
    write_exec(hook, "#!/bin/sh\nexit 0\n")
    hardlink_editmsg_to_hook(gg, repo, hook, str(payload(tmp_path)))
    (repo / ".git/COMMIT_EDITMSG").unlink()                 # the link removed
    gg.git("commit", "-q", "--amend", "--no-edit", cwd=repo)
    assert not (tmp_path / "RAN").exists()


@pytest.mark.skipif(not git_has("alias_subsection"), reason="git without `[alias \"x\"] command`")
def test_alias_subsection_control_real_git_runs_it(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[90] git 2.54 runs `git ci` with the alias's hooksPath."""
    _cs.attack_alias_subsection_config_hookspath(gg, repo, tmp_path)
    (repo / "f").write_text("b\n")
    gg.git("ci", "-qam", "x", cwd=repo)
    assert (tmp_path / "RAN").exists()


@pytest.mark.skipif(not git_has("optional_path"), reason="git without `:(optional)` paths")
@pytest.mark.parametrize("scope", ["local", "global"])
def test_optional_hookspath_control_real_git_runs_it(gg: GG, repo: Path, tmp_path: Path,
                                                     scope: str) -> None:
    """[91] git 2.52+ strips `:(optional)` and runs `.githooks/post-checkout`."""
    getattr(_cs, f"attack_optional_hookspath_{scope}")(gg, repo, tmp_path)
    gg.git("checkout", "-q", "-b", "x", cwd=repo)
    assert (tmp_path / "RAN").exists()


def _submodule_update(gg: GG, repo: Path, tmp_path: Path) -> None:
    """Leave the submodule one commit behind (that checkout runs the hook
    too: the mark is cleared after it), then `git submodule update`."""
    gg.git("checkout", "-q", "HEAD~1", cwd=repo / "sub")
    (tmp_path / "RAN").unlink(missing_ok=True)
    gg.git("submodule", "-q", "update", cwd=repo)


@pytest.mark.skipif(not git_has("config_hooks"), reason="git without config-based hooks")
def test_global_config_hook_submodule_control_real_git_runs_it(gg: GG, repo: Path,
                                                               tmp_path: Path) -> None:
    """[92] git 2.54 runs the global config hook in the submodule's tree."""
    _cs.attack_global_config_hook_relative_in_submodule(gg, repo, tmp_path)
    _submodule_update(gg, repo, tmp_path)
    assert (tmp_path / "RAN").exists()


def test_shared_include_submodule_control_real_git_runs_it(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[93] git applies the shared include's hooksPath in the submodule."""
    _cs.attack_shared_include_in_superproject_and_submodule(gg, repo, tmp_path)
    _submodule_update(gg, repo, tmp_path)
    assert (tmp_path / "RAN").exists()


def test_symlinked_include_control_real_git_runs_it(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[94] git reads `shared/local.inc`, next to the link."""
    _cs.attack_relative_include_inside_symlinked_include(gg, repo, tmp_path)
    gg.git("status", cwd=repo)
    assert (tmp_path / "RAN").exists()


@pytest.mark.parametrize("attack", [_cs.attack_ssh_config_glued_to_short_option,
                                    _cs.attack_ssh_config_glued_in_option_cluster])
def test_glued_ssh_option_control_real_git_runs_it(gg: GG, repo: Path, tmp_path: Path,
                                                   attack) -> None:
    """[96] ssh reads the glued `-F` file, alone or in a cluster: its
    ProxyCommand runs."""
    attack(gg, repo, tmp_path)
    gg.git("fetch", "-q", "origin", cwd=repo)
    assert (tmp_path / "RAN").exists()


# ------------------------------------------------ the marker, 15th pass [104]–[112]
def test_served_repository_marker_covers_it_alone(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[105] a trusted post-receive of a local hub runs `cd site && git pull`:
    the hub's children inherit a marker for the hub, not for `site`, whose
    planted post-merge must not run. The child judges `site`, refuses at
    once (no terminal to ask) and records. Control: raw children run it."""
    mark = tmp_path / "RAN"
    hub, site = tmp_path / "hub.git", tmp_path / "site"
    assert gg.git("init", "-q", "--bare", str(hub)).rc == 0
    gg.git("remote", "add", "hub", str(hub), cwd=repo)
    assert gg.git("push", "-q", "hub", "main", cwd=repo).rc == 0
    assert gg.git("clone", "-q", str(hub), str(site)).rc == 0
    write_exec(hub / "hooks/post-receive",
               f"#!/bin/sh\ncd {site} && unset GIT_DIR && git pull -q origin main\n")
    gg.trust(repo)
    gg.trust(site)
    write_exec(site / ".git/hooks/post-merge", f"#!/bin/sh\ntouch {mark}\n")     # the sandbox
    (repo / "f").write_text("2\n")
    gg.git("commit", "-qam", "2", cwd=repo)
    r = gg.run("git", "push", "-q", "hub", "main", cwd=repo)
    assert r.rc == 0 and not mark.exists(), r.text
    assert Path(str(gg.key_for(site)) + ".pending").exists(), "the child's refusal is recorded"
    (repo / "f").write_text("3\n")
    gg.git("commit", "-qam", "3", cwd=repo)
    assert gg.git("push", "-q", "hub", "main", cwd=repo).rc == 0
    assert mark.exists(), "control: the real git's hook runs the pull, which runs post-merge"


def test_server_as_first_word_passes_through(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[106] `git upload-pack <dir>` / `git receive-pack <dir>` as the first
    word (git daemon, http-backend, git-shell) serve the named repository
    and read nothing of the cwd: passed through like the dashed names."""
    bare = tmp_path / "srv.git"
    assert gg.git("init", "-q", "--bare", str(bare)).rc == 0
    write_exec(repo / ".git/hooks/pre-commit")           # cwd modified: irrelevant
    for cmd in (["upload-pack", "--advertise-refs", str(bare)],
                ["receive-pack", "--advertise-refs", str(bare)],
                ["upload-pack", "--timeout", "5", "--advertise-refs", str(bare)]):
        r = gg.run("git", *cmd, cwd=repo)
        assert r.rc == 0 and "gitguard" not in r.err and r.out, (cmd, r.text)
    assert gg.check(repo).blocked
    assert gg.run("git", "-C", str(repo), "upload-pack", str(bare), cwd=tmp_path).blocked, \
        "a global option first: the full check"


def test_child_clone_is_auto_trusted_unless_covered(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[107] a clone run by a child git (an alias, a hook, pre-commit's
    cache) is the user's clone: marker, wait, auto-trust. One the marker
    covers — `submodule add`'s clone into `modules/<x>` — leaves no state
    of its own: the parent's next command sees the new gitdir and asks."""
    src = make_source(gg, tmp_path)
    cache = tmp_path / "cache"
    gg.git("config", "alias.getit", f"!git clone -q file://{src} {cache}", cwd=repo)
    gg.trust(repo)
    r = gg.run("git", "getit", cwd=repo)
    assert r.rc == 0 and "new repository trusted" in r.err, r.text
    assert not gg.check(cache).blocked
    r = gg.run("git", "-c", "protocol.file.allow=always", "submodule", "add", "-q", str(src), "sub", cwd=repo)
    assert r.rc == 0 and "trusted" not in r.err, r.text
    assert not gg.key_for(repo / "sub").exists(), "a covered clone registers nothing"
    assert gg.check(repo).blocked, "the parent's next command sees modules/sub"


def test_submodule_push_children_judged_on_their_destination(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[108] a covered child's push is judged on where it goes, not under
    its own key: `push --recurse-submodules=on-demand` pushes the
    submodule, an alias `push -u && push --tags` survives its own branch
    tracking write; a push to a path no trusted config names is still
    refused ([62]), with the planted pre-receive never run."""
    from tests.attacks._helpers import add_submodule
    sub = add_submodule(gg, repo, tmp_path)
    hub, subhub, evil = tmp_path / "hub.git", tmp_path / "subhub.git", tmp_path / "evil.git"
    for b in (hub, subhub, evil):
        assert gg.git("init", "-q", "--bare", str(b)).rc == 0
    mark = tmp_path / "RAN"
    write_exec(evil / "hooks/pre-receive", f"#!/bin/sh\ntouch {mark}\n")
    gg.git("remote", "add", "hub", str(hub), cwd=repo)
    gg.git("remote", "add", "hub", str(subhub), cwd=sub)
    (sub / "s").write_text("s2\n")
    gg.git("commit", "-qam", "s2", cwd=sub)
    gg.git("commit", "-qam", "sub2", cwd=repo)
    gg.git("config", "alias.pp", "!git push -q -u hub main && git push -q --tags hub", cwd=repo)
    gg.git("config", "alias.pe", f"!git push -q {evil} main", cwd=repo)
    gg.git("tag", "v1", cwd=repo)
    gg.trust(repo)
    r = gg.run("git", "push", "-q", "--recurse-submodules=on-demand", "hub", "main", cwd=repo)
    assert r.rc == 0 and "✗" not in r.err, r.text
    assert gg.git("--git-dir", str(subhub), "rev-parse", "main").rc == 0, "the submodule was pushed"
    r = gg.run("git", "pp", cwd=repo)
    assert r.rc == 0 and "✗" not in r.err, r.text
    assert gg.git("--git-dir", str(hub), "rev-parse", "v1").rc == 0
    r = gg.run("git", "pe", cwd=repo)
    assert r.rc != 0 and "[62]" in r.err and not mark.exists(), r.text


def test_device_in_a_config_value_is_no_path(gg: GG, repo: Path) -> None:
    """[109] `/dev/null` in an alias, global or local: nothing to watch.
    It refused every repository as an unreadable directory, `trust` too."""
    gg.git("config", "--global", "alias.q", "!git status >/dev/null")
    gg.git("config", "alias.n", "!cat /dev/null", cwd=repo)
    r = gg.run("trust", cwd=repo)
    assert r.rc == 0 and "/dev/null" not in r.err, r.text
    assert not gg.check(repo).blocked
    assert gg.run("git", "q", cwd=repo).rc == 0


def test_child_with_another_work_tree_is_judged(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[111] a trusted alias `!git --work-tree=<site> checkout -f main` with a
    relative core.hooksPath: the child runs the hooks of `<site>/.githooks`,
    which nothing judged. The same gitdir with another tree is another
    repository: judged, refused (never trusted / changed), the planted
    post-checkout never runs. Control: the raw child runs it."""
    mark = tmp_path / "RAN"
    site = tmp_path / "site"
    site.mkdir()
    write_exec(repo / ".githooks/post-checkout", "#!/bin/sh\nexit 0\n")
    gg.git("config", "core.hooksPath", ".githooks", cwd=repo)
    gg.git("config", "alias.deploy", f"!git --work-tree={site} checkout -q -f main", cwd=repo)
    gg.trust(repo)
    write_exec(site / ".githooks/post-checkout", f"#!/bin/sh\ntouch {mark}\n")      # the sandbox
    r = gg.run("git", "deploy", cwd=repo)
    assert r.rc != 0 and not mark.exists(), r.text
    assert gg.git("deploy", cwd=repo).rc == 0 and mark.exists(), "control: git runs it"


def test_real_git_naming_gitguard_is_refused(gg: GG, repo: Path) -> None:
    """[112] GITGUARD_REAL_GIT = gitguard itself: refused, not exec'd for ever."""
    import subprocess
    from tests.conftest import GITGUARD
    env = dict(gg.env, GITGUARD_REAL_GIT=str(GITGUARD))
    r = subprocess.run([sys.executable, str(GITGUARD), "git", "status"], cwd=repo, env=env,
                       capture_output=True, text=True, timeout=30)
    assert r.returncode != 0 and "names gitguard itself" in r.stderr, r.stderr


def _planted_gitdir(gg: GG, tmp_path: Path, mark: Path) -> Path:
    """[113] The sandbox: a gitdir in the volume with a planted hook, for a
    `--separate-git-dir` the project's README names."""
    g = tmp_path / "ws" / "meta.git"
    assert gg.git("init", "-q", "--bare", str(g)).rc == 0
    write_exec(g / "hooks/pre-commit", f"#!/bin/sh\ntouch {mark}\n")
    return g


def _commit_in(gg: GG, proj: Path, guarded: bool) -> None:
    """A commit in `proj` through gitguard, or with the raw git (control)."""
    import subprocess
    (proj / "f").write_text("x\n")
    for a in (["add", "f"], ["commit", "-qm", "one"]):
        subprocess.run([sys.executable, str(GITGUARD), "git", *a] if guarded else ["git", *a],
                       cwd=proj, env=gg.env if guarded else gg.raw_env, capture_output=True)


def test_init_separate_git_dir_into_an_existing_gitdir_is_not_trusted(gg: GG, tmp_path: Path) -> None:
    """[113] `init --separate-git-dir=<X>` with X already a gitdir
    reinitialises X and keeps its hooks and config; gitguard looked for a
    pre-existing repository at `<dir>/.git` only, and trusted X."""
    mark = tmp_path / "RAN"
    g = _planted_gitdir(gg, tmp_path, mark)
    proj = tmp_path / "proj"
    proj.mkdir()
    r = gg.run("git", "init", "-q", f"--separate-git-dir={g}", str(proj), cwd=tmp_path)
    assert r.rc == 0 and "new repository trusted" not in r.err, r.text
    _commit_in(gg, proj, True)
    assert not mark.exists(), "the planted pre-commit of the reinitialised gitdir ran"


def test_init_separate_git_dir_control_real_git_runs_it(gg: GG, tmp_path: Path) -> None:
    """[113] positive control."""
    mark = tmp_path / "RAN"
    g = _planted_gitdir(gg, tmp_path, mark)
    proj = tmp_path / "proj"
    proj.mkdir()
    assert gg.git("init", "-q", f"--separate-git-dir={g}", str(proj)).rc == 0
    _commit_in(gg, proj, False)
    assert mark.exists(), "git no longer keeps an existing gitdir's hooks on reinit: [113] may be moot"


def test_empty_template_is_no_template(gg: GG, tmp_path: Path) -> None:
    """[116] `init --template=` (pre-commit's cache repositories) copies no
    template at all, a configured one included: auto-trusted. A real
    template still withholds it ([42])."""
    tpl = tmp_path / "tpl"
    (tpl / "hooks").mkdir(parents=True)
    gg.git("config", "--global", "init.templateDir", str(tpl))
    for form in (["--template="], ["--template", ""]):
        d = tmp_path / f"cache{len(form)}"
        r = gg.run("git", "init", "-q", *form, str(d), cwd=tmp_path)
        assert r.rc == 0 and "new repository trusted" in r.err, r.text
        assert not (d / ".git/hooks").exists(), "git copied a template: [116] reading wrong"
        assert gg.run("git", "remote", "add", "origin", "file:///x", cwd=d).rc == 0
    r = gg.run("git", "init", "-q", f"--template={tpl}", str(tmp_path / "t"), cwd=tmp_path)
    assert r.rc == 0 and "new repository trusted" not in r.err, r.text


# --------------------------------- a child at another work tree root [115] [120]–[122]
def _husky_worktree(gg: GG, tmp_path: Path, mark: Path) -> tuple[Path, Path]:
    """[120] husky's layout (`core.hooksPath = .husky/_`, the directory
    ignored), a linked worktree the sandbox works in, both trusted; the
    sandbox drops `.husky/_/post-index-change` in its worktree (ignored:
    the tree stays clean) and touches a tracked file."""
    main, wt = tmp_path / "main", tmp_path / "wt"
    gg.git("init", "-q", str(main))
    (main / ".husky/_").mkdir(parents=True)
    (main / ".husky/_/.gitignore").write_text("*\n")
    write_exec(main / ".husky/_/pre-commit", "#!/bin/sh\nexit 0\n")
    (main / "a").write_text("a\n")
    gg.git("add", "a", cwd=main)
    gg.git("commit", "-qm", "a", cwd=main)
    gg.git("config", "core.hooksPath", ".husky/_", cwd=main)
    gg.git("worktree", "add", "-q", "-b", "agent", str(wt), cwd=main)
    (wt / ".husky/_").mkdir(parents=True)
    (wt / ".husky/_/.gitignore").write_text("*\n")
    write_exec(wt / ".husky/_/pre-commit", "#!/bin/sh\nexit 0\n")
    gg.trust(main)
    gg.trust(wt)
    write_exec(wt / ".husky/_/post-index-change", f"#!/bin/sh\ntouch {mark}\n")
    import time
    time.sleep(1.1)           # past the index's timestamp: `status` refreshes the entry, post-index-change fires
    (wt / "a").touch()
    return main, wt


def test_worktree_remove_judges_the_linked_worktree(gg: GG, tmp_path: Path) -> None:
    """[120] `worktree remove` runs `git status` in the linked worktree: a
    child whose gitdir the parent hashed, but whose tree it did not — the
    hooks a relative `core.hooksPath` names there. Covered, it ran the
    sandbox's hook, then deleted the worktree, evidence included."""
    mark = tmp_path / "RAN"
    main, wt = _husky_worktree(gg, tmp_path, mark)
    gg.run("git", "worktree", "remove", str(wt), cwd=main)
    assert not mark.exists(), "the hook planted in the linked worktree ran"


def test_worktree_remove_control_real_git_runs_it(gg: GG, tmp_path: Path) -> None:
    """[120] positive control."""
    mark = tmp_path / "RAN"
    main, wt = _husky_worktree(gg, tmp_path, mark)
    import subprocess
    subprocess.run(["git", "worktree", "remove", str(wt)], cwd=main, env=gg.raw_env, capture_output=True)
    assert mark.exists(), "worktree remove no longer refreshes the worktree's index: [120] may be moot"


def _deploy_remote(gg: GG, tmp_path: Path) -> tuple[Path, Path]:
    """A non-bare local remote with `receive.denyCurrentBranch =
    updateInstead` (push-to-deploy), and the user's clone of it, trusted."""
    deploy, proj = tmp_path / "deploy", tmp_path / "proj"
    gg.git("init", "-q", str(deploy))
    (deploy / "a").write_text("a\n")
    gg.git("add", "a", cwd=deploy)
    gg.git("commit", "-qm", "a", cwd=deploy)
    gg.git("branch", "feature", cwd=deploy)
    gg.git("config", "receive.denyCurrentBranch", "updateInstead", cwd=deploy)
    gg.git("clone", "-q", str(deploy), str(proj))
    gg.trust(proj)
    (proj / "b").write_text("b\n")
    gg.git("add", "b", cwd=proj)
    gg.git("commit", "-qm", "b", cwd=proj)
    return deploy, proj


def _plant_served_worktree(deploy: Path, mark: Path, inside: bool) -> None:
    """[121] A linked worktree planted in the remote's gitdir, its own gitdir
    root (or, `inside`, its commondir a root planted under `modules/`),
    with a core.fsmonitor: push-to-deploy refreshes the index there."""
    import shutil
    g = deploy / ".git"
    pc = g / ("modules/x" if inside else "worktrees/evil")
    (pc / "refs/heads").mkdir(parents=True)
    shutil.copytree(g / "objects", pc / "objects")
    shutil.copy(g / "HEAD", pc / "HEAD")
    for r in (g / "refs/heads").iterdir():
        shutil.copy(r, pc / "refs/heads" / r.name)
    write_exec(deploy.parent / "fsm.sh", f"#!/bin/sh\ntouch {mark}\n")
    (pc / "config").write_text(f"[core]\n\trepositoryformatversion = 0\n\tbare = false\n"
                               f"\tfsmonitor = {deploy.parent / 'fsm.sh'}\n")
    w = g / "worktrees/evil"
    w.mkdir(parents=True, exist_ok=True)
    (w / "HEAD").write_text("ref: refs/heads/feature\n")
    if inside:
        (w / "commondir").write_text("../../modules/x\n")
    tree = deploy.parent / "evtree"
    tree.mkdir()
    (w / "gitdir").write_text(f"{tree}/.git\n")
    shutil.copy(g / "index", w / "index")
    (tree / ".git").write_text(f"gitdir: {w}\n")
    (tree / "a").write_text("a\n")


@pytest.mark.parametrize("inside", [False, True])
def test_served_marker_covers_the_served_gitdir_alone(gg: GG, tmp_path: Path, inside: bool) -> None:
    """[121] The served repository's marker covered every gitdir root under
    it; the push hashed none of them (a local push watches the remote's
    config and hooks, not its `worktrees/` or `modules/`). It covers the
    served gitdir and common dir, exactly."""
    mark = tmp_path / "RAN"
    deploy, proj = _deploy_remote(gg, tmp_path)
    _plant_served_worktree(deploy, mark, inside)
    gg.run("git", "push", "-q", "origin", "HEAD:feature", cwd=proj)
    assert not mark.exists(), "the planted worktree's fsmonitor ran during push-to-deploy"


@pytest.mark.parametrize("inside", [False, True])
def test_served_worktree_control_real_git_runs_it(gg: GG, tmp_path: Path, inside: bool) -> None:
    """[121] positive control."""
    import subprocess
    mark = tmp_path / "RAN"
    deploy, proj = _deploy_remote(gg, tmp_path)
    _plant_served_worktree(deploy, mark, inside)
    subprocess.run(["git", "push", "-q", "origin", "HEAD:feature"], cwd=proj, env=gg.raw_env,
                   capture_output=True)
    assert mark.exists(), "push-to-deploy no longer refreshes a linked worktree's index: [121] may be moot"


def _deploy_tree_hook(gg: GG, tmp_path: Path, mark: Path) -> Path:
    """[122] The remote's trusted config names a hooks directory in its tree
    (`core.hooksPath = .githooks`); the sandbox writes one file there."""
    deploy, proj = _deploy_remote(gg, tmp_path)
    (deploy / ".githooks").mkdir()
    gg.git("config", "core.hooksPath", ".githooks", cwd=deploy)
    gg.trust(proj)                      # the remote's config is watched by the push
    write_exec(deploy / ".githooks/post-index-change", f"#!/bin/sh\ntouch {mark}\n")
    return proj


def test_push_to_deploy_children_judge_the_remote_tree(gg: GG, tmp_path: Path) -> None:
    """[122] push-to-deploy's `update-index`/`read-tree` run in the remote's
    work tree; the served marker has no root and covered them whatever
    their tree: they ran a hook from it nobody hashed."""
    mark = tmp_path / "RAN"
    proj = _deploy_tree_hook(gg, tmp_path, mark)
    gg.run("git", "push", "-q", "origin", "main", cwd=proj)
    assert not mark.exists(), "a hook in the remote's work tree ran during push-to-deploy"


def test_push_to_deploy_tree_hook_control_real_git_runs_it(gg: GG, tmp_path: Path) -> None:
    """[122] positive control."""
    import subprocess
    mark = tmp_path / "RAN"
    proj = _deploy_tree_hook(gg, tmp_path, mark)
    subprocess.run(["git", "push", "-q", "origin", "main"], cwd=proj, env=gg.raw_env, capture_output=True)
    assert mark.exists(), "push-to-deploy no longer runs post-index-change: [122] may be moot"


def test_child_maintenance_stays_in_the_command(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[117] git ≥ 2.47 runs `maintenance run --auto --detach`, which
    daemonizes: its gc, repack, prune left the command's process tree, the
    marker was dead for them, and in a submodule (never trusted under its
    own key) gc was refused at every fetch, recorded, notified. A child
    git does not detach: the auto-gc is done before the command returns,
    nothing is recorded."""
    from tests.attacks._helpers import add_submodule
    import subprocess
    sub = add_submodule(gg, repo, tmp_path)
    src = tmp_path / "subsrc"
    objs = tmp_path / "objs"
    objs.mkdir()
    for i in range(600):
        (objs / str(i)).write_text(f"o{i}\n")
    subprocess.run(["git", "hash-object", "-w", "--stdin-paths"], cwd=sub, env=gg.raw_env, check=True,
                   input="\n".join(str(objs / str(i)) for i in range(600)), text=True,
                   capture_output=True)
    gg.git("config", "gc.auto", "1", cwd=sub)
    gg.trust(repo)
    commit(gg, src, "u", "2")
    loose = lambda: sum(1 for d in (repo / ".git/modules/sub/objects").glob("??") for _ in d.iterdir())
    before = loose()
    r = gg.run("git", "-c", "protocol.file.allow=always", "submodule", "update", "--remote", cwd=repo)
    assert r.rc == 0 and "✗" not in r.err, r.text
    assert loose() < before, "the submodule's auto-gc did not run within the command"
    assert not list(gg.state.glob("*.pending")), "a maintenance child was judged as a top-level command"


def test_upload_archive_writer_serves_its_argument(gg: GG, tmp_path: Path) -> None:
    """[118] `upload-archive` (sshd runs it from `~`) starts `git
    upload-archive--writer <dir>`, which enters `<dir>` itself: a server
    like the others ([106]). Judged against its cwd, every `archive
    --remote` failed where `~` is a repository nobody trusted."""
    import subprocess
    src, hub, home = tmp_path / "src", tmp_path / "hub.git", tmp_path / "home"
    gg.git("init", "-q", str(src))
    commit(gg, src, "a", "a")
    gg.git("clone", "-q", "--bare", str(src), str(hub))
    gg.git("init", "-q", str(home))
    r = subprocess.run([sys.executable, str(GITGUARD), "git", "upload-archive", str(hub)], cwd=home,
                       env=gg.env, input=b"0012argument HEAD\n0000", capture_output=True)
    assert r.returncode == 0 and b"never trusted" not in r.stdout + r.stderr, r.stderr


def test_exec_path_shim_is_built_and_checked(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[119] `gitguard exec-path <dir>` builds the exec path a macOS install
    points GIT_EXEC_PATH at: every entry of the real git's exec path,
    `git` → gitguard, `git.real` → the real binary (a GUI app's PATH has
    only Apple's git: without it the real git became that one). `trust`
    says when the directory is stale (an upgrade removed or added
    entries), and names `gitguard exec-path`, not a Debian command."""
    import subprocess
    shim = tmp_path / "shim"
    env = {k: v for k, v in gg.env.items() if k != "GIT_EXEC_PATH"}
    r = subprocess.run([sys.executable, str(GITGUARD), "exec-path", str(shim)], env=env,
                       capture_output=True, text=True)
    assert r.returncode == 0 and str(shim) in r.stdout, r.stderr
    assert (shim / "git").resolve() == GITGUARD.resolve()
    core = Path(subprocess.run([REAL_GIT, "--exec-path"], env=env, capture_output=True,
                               text=True).stdout.strip())
    assert (shim / "git.real").resolve() != GITGUARD.resolve() and (shim / "git.real").is_file()
    assert {p.name for p in core.iterdir()} | {"git.real"} >= {p.name for p in shim.iterdir()}
    wenv = dict(env, GIT_EXEC_PATH=str(shim))
    t = subprocess.run([sys.executable, str(GITGUARD), "trust"], cwd=repo, env=wenv, capture_output=True, text=True)
    assert t.returncode == 0 and "exec path" not in t.stderr, t.stderr
    victim = next(p for p in shim.iterdir() if p.name not in ("git", "git.real"))
    victim.unlink()
    (shim / "git-gone").symlink_to(tmp_path / "nowhere")
    t = subprocess.run([sys.executable, str(GITGUARD), "trust"], cwd=repo, env=wenv, capture_output=True, text=True)
    assert "stale" in t.stderr and "gitguard exec-path" in t.stderr, t.stderr
    t = subprocess.run([sys.executable, str(GITGUARD), "trust"], cwd=repo, env=env, capture_output=True, text=True)
    assert "does not lead to gitguard" in t.stderr, t.stderr
    if not Path("/usr/bin/dpkg-divert").exists():
        assert "dpkg-divert" not in t.stderr and "gitguard exec-path" in t.stderr, t.stderr


# --------------------------------------------------- [126] pathspec activation
def test_trust_warns_on_a_pathspec_activation(gg: GG, tmp_path: Path) -> None:
    """[126] With the fsmonitor pin off (GITGUARD_KEEP_FSMONITOR), `trust`
    names the hazard of a `submodule.active` pathspec (what `clone
    --recurse-submodules` writes) and the way out; with the pin on, the
    hazard is disarmed and nothing is said; per-name activation, a hashed
    write, gets no warning either way."""
    r = tmp_path / "r"
    gg.git("init", "-q", str(r))
    assert gg.git("config", "submodule.active", ".", cwd=r).rc == 0
    assert "submodule.active" not in gg.trust(r).err
    gg.env["GITGUARD_KEEP_FSMONITOR"] = "1"
    assert gg.git("config", "--unset-all", "submodule.active", cwd=r).rc == 0
    assert gg.git("config", "submodule.sub.active", "true", cwd=r).rc == 0
    assert "submodule.active" not in gg.trust(r).err
    assert gg.git("config", "submodule.active", ".", cwd=r).rc == 0
    res = gg.run("trust", cwd=r)
    assert res.rc == 0, res.text
    assert "submodule.active = ." in res.err and "unset-all" in res.err, res.text


def test_clone_autotrust_warns_on_the_pathspec_it_writes(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[126] `clone --recurse-submodules` is what writes `submodule.active = .`,
    and its auto-trust is where the user is: the warning and the way out
    are printed there, not only at a later `trust`. A plain clone of the
    same source, which activates nothing, gets no warning."""
    from tests.attacks._helpers import add_submodule
    add_submodule(gg, repo, tmp_path)
    r = gg.run("git", "clone", "-q", "--recurse-submodules", str(repo), "pinned", cwd=tmp_path)
    assert r.rc == 0 and "new repository trusted" in r.err, r.text
    assert "submodule.active" not in r.err, r.text          # disarmed by the pin
    assert not gg.check(tmp_path / "pinned").blocked
    gg.env["GITGUARD_KEEP_FSMONITOR"] = "1"
    r = gg.run("git", "clone", "-q", "--recurse-submodules", str(repo), "rec", cwd=tmp_path)
    assert r.rc == 0 and "new repository trusted" in r.err, r.text
    assert "submodule.active = ." in r.err and "unset-all" in r.err, r.text
    assert not gg.check(tmp_path / "rec").blocked
    r = gg.run("git", "clone", "-q", str(repo), "plain", cwd=tmp_path)
    assert r.rc == 0 and "new repository trusted" in r.err, r.text
    assert "submodule.active" not in r.err, r.text


# ------------------------------------------------- PINNED_CONFIG: the fsmonitor pin
def test_pinned_config_reaches_git_after_the_users_parameters(gg: GG, repo: Path) -> None:
    """The pin is appended to GIT_CONFIG_PARAMETERS in git's own format: git
    reads both the user's words and gitguard's (an ill-formed list makes
    every command die "bogus format"); the user's `-c` comes after it in
    git's list and wins, their own input; GITGUARD_KEEP_FSMONITOR drops
    the pin."""
    gg.env["GIT_CONFIG_PARAMETERS"] = "'user.name'='x y' 'core.fsmonitor'='./it'"
    r = gg.run("git", "config", "--get-all", "core.fsmonitor", cwd=repo)
    assert r.rc == 0 and r.out.splitlines() == ["./it", "false"], r.text
    r = gg.run("git", "config", "--get", "user.name", cwd=repo)
    assert r.rc == 0 and r.out.strip() == "x y", r.text
    r = gg.run("git", "-c", "core.fsmonitor=./mine", "config", "--get-all", "core.fsmonitor", cwd=repo)
    assert r.rc == 0 and r.out.splitlines() == ["./it", "false", "./mine"], r.text
    gg.env["GITGUARD_KEEP_FSMONITOR"] = "1"
    r = gg.run("git", "config", "--get-all", "core.fsmonitor", cwd=repo)
    assert r.rc == 0 and r.out.splitlines() == ["./it"], r.text
    del gg.env["GIT_CONFIG_PARAMETERS"], gg.env["GITGUARD_KEEP_FSMONITOR"]
    r = gg.run("git", "config", "--get-all", "core.fsmonitor", cwd=repo)
    assert r.rc == 0 and r.out.splitlines() == ["false"], r.text
    assert gg.run("git", "--version", cwd=repo).rc == 0          # the passthrough is pinned too
