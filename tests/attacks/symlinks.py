"""Symlinks: redirection of .git, refs/, hooks, and links added at depth."""
from __future__ import annotations

import os
from pathlib import Path

from tests.conftest import GG, write_exec


def attack_git_is_symlink(gg: GG, repo: Path, tmp_path: Path) -> None:
    """.git itself replaced by a symlink"""
    (repo / ".git").rename(repo / ".git.real")
    os.symlink(".git.real", repo / ".git")


def attack_refs_symlink(gg: GG, repo: Path, tmp_path: Path) -> None:
    """refs/ replaced by a symlink to the outside (host git would write its refs there)"""
    (repo / ".git/refs").rename(repo / ".git/refs.bak")
    os.symlink(tmp_path / "home", repo / ".git/refs")


def attack_symlink_in_hooks_depth2(gg: GG, repo: Path, tmp_path: Path) -> None:
    """symlink added in .git/hooks (depth 2)"""
    os.symlink("/tmp", repo / ".git/hooks/evil")


def attack_symlink_hook_in_submodule_depth4(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[2] symlink hook in .git/modules/sub/hooks (depth 4, beyond the structural check)"""
    from tests.attacks._helpers import add_submodule
    add_submodule(gg, repo, tmp_path)
    gg.trust(repo)
    write_exec(repo / "payload.sh")
    os.symlink("../../../../payload.sh", repo / ".git/modules/sub/hooks/pre-commit")


def attack_symlink_in_hookspath_dir(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[2] symlink added in the tree's core.hooksPath directory"""
    (repo / ".githooks").mkdir()
    gg.git("config", "core.hooksPath", ".githooks", cwd=repo)
    gg.trust(repo)
    write_exec(repo / "payload.sh")
    os.symlink("../payload.sh", repo / ".githooks/pre-commit")


def attack_lock_suffixed_symlink_deep(gg: GG, repo: Path, tmp_path: Path) -> None:
    """symlink named *.lock at depth >= 3: skipped by walk_gitdir's .lock skip
    (appended to filenames then excluded) and below the structural symlink
    check (2 levels only) → invisible to the fingerprint. Latent: no known
    execution vector at this position, but it violates the invariant "no
    gitdir symlink escapes watching"."""
    d = repo / ".git/a/b"
    d.mkdir(parents=True)
    os.symlink(tmp_path / "home", d / "evil.lock")


def attack_hookspath_file_replaced_by_symlink(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[3] hooksPath file replaced by a symlink (restore target)"""
    write_exec(repo / ".githooks/pre-commit", "#!/bin/sh\nexit 0\n")
    gg.git("config", "core.hooksPath", ".githooks", cwd=repo)
    gg.trust(repo)
    (repo / ".githooks/pre-commit").unlink()
    os.symlink("/tmp/x", repo / ".githooks/pre-commit")


def attack_tree_hook_symlink_into_volatile(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[22] hooksPath hook = symlink to .git/logs/blob (volatile): fingerprinted
    by its target string only, content not fingerprinted → invisible rewrite"""
    (repo / ".githooks").mkdir()
    blob = repo / ".git/logs/blob"
    blob.parent.mkdir(parents=True, exist_ok=True)
    write_exec(blob, "#!/bin/sh\nexit 0\n")
    os.symlink("../.git/logs/blob", repo / ".githooks/pre-commit")
    gg.git("config", "core.hooksPath", ".githooks", cwd=repo)
    gg.run("trust", cwd=repo)           # refusal at trust time is accepted (volatile zone)
    write_exec(blob)


def attack_tree_hook_symlink_to_tree_file(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[22] hooksPath hook = symlink to an unwatched tree file (scripts/hook.sh):
    the target is rewritten, the link's fingerprint does not move"""
    (repo / ".githooks").mkdir()
    write_exec(repo / "scripts/hook.sh", "#!/bin/sh\nexit 0\n")
    os.symlink("../scripts/hook.sh", repo / ".githooks/pre-commit")
    gg.git("config", "core.hooksPath", ".githooks", cwd=repo)
    gg.trust(repo)
    write_exec(repo / "scripts/hook.sh")


def attack_module_hooks_dir_symlink_deep(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[22] .git/modules/sub/hooks → unwatched directory (depth 3, beyond the
    2-level structural check): the submodule's hooks rewritten"""
    from tests.attacks._helpers import add_submodule
    add_submodule(gg, repo, tmp_path)
    gg.trust(repo)
    hooks = repo / ".git/modules/sub/hooks"
    import shutil
    shutil.rmtree(hooks)
    ext = tmp_path / "exthooks"
    write_exec(ext / "post-checkout", "#!/bin/sh\nexit 0\n")
    os.symlink(ext, hooks)
    gg.run("trust", cwd=repo)           # refused at trust time (link to a directory): accepted
    write_exec(ext / "post-checkout")    # then the target changes, outside the fingerprint


def attack_lost_found_symlink_for_fsck(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[83] a symlink at .git/lost-found/other/<sha> onto a hook, with a
    dangling blob of that sha holding hook content: `git fsck --lost-found`
    writes the blob there, through the link. lost-found/ stays watched"""
    import subprocess
    sha = subprocess.run(["git", "hash-object", "-w", "--stdin"], cwd=repo, env=gg.env,
                         input="#!/bin/sh\ntouch /tmp/evil\n", capture_output=True, text=True,
                         check=True).stdout.strip()
    (repo / ".git/lost-found/other").mkdir(parents=True)
    (repo / ".git/lost-found/other" / sha).symlink_to("../../hooks/post-commit")
