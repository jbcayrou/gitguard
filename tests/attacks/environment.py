"""Repository-local variables of the user's environment that move git's
files elsewhere: GIT_COMMON_DIR (config, hooks, info/, worktrees/, and the
objects/refs test of discovery), GIT_INDEX_FILE (the gitlinks). [54]

The sandbox cannot set them; a script, a Makefile or a tool of the user
can, and the value may name a directory or a file of the volume, which the
sandbox fills.
"""
from __future__ import annotations

import shutil
from pathlib import Path

from tests.conftest import GG, write_exec


def _planted_gitdir(repo: Path, tmp_path: Path) -> Path:
    """A complete gitdir of the sandbox's own: a copy of the repository's,
    with a config that executes."""
    evil = tmp_path / "evil"
    shutil.copytree(repo / ".git", evil)
    with open(evil / "config", "a") as f:
        f.write("[core]\n\tfsmonitor = /tmp/evil\n")
    return evil


def attack_env_common_dir_planted_gitdir(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[54] GIT_COMMON_DIR naming a gitdir the sandbox wrote: git reads its
    config and runs its hooks, gitguard fingerprinted .git"""
    gg.env["GIT_COMMON_DIR"] = str(_planted_gitdir(repo, tmp_path))


def attack_env_common_dir_hook_after_trust(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[54] GIT_COMMON_DIR trusted as a benign directory of the volume, then
    a hook is dropped there"""
    common = tmp_path / "vol-common"
    shutil.copytree(repo / ".git", common)
    gg.env["GIT_COMMON_DIR"] = str(common)
    gg.trust(repo)
    write_exec(common / "hooks/pre-commit")


def attack_env_common_dir_head_planted_in_subdir(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[54] with GIT_COMMON_DIR, a lone HEAD file makes `src/` a gitdir for
    git's discovery (objects and refs are looked up in the common dir)"""
    gg.env["GIT_COMMON_DIR"] = str(_planted_gitdir(repo, tmp_path))
    (repo / "src").mkdir()
    (repo / "src/HEAD").write_text("ref: refs/heads/main\n")


def attack_env_index_file_forged_gitlink(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[54] GIT_INDEX_FILE naming an index of the volume whose gitlink points
    at a nested trapped repository; .git/index has no gitlink"""
    sub = repo / "vendor"
    sub.mkdir()
    gg.git("init", "-q", cwd=sub)
    (sub / "v").write_text("v\n")
    gg.git("add", "v", cwd=sub)
    gg.git("commit", "-qm", "v", cwd=sub)
    gg.git("config", "core.fsmonitor", "/tmp/evil", cwd=sub)
    gg.env["GIT_INDEX_FILE"] = str(repo / "forged.idx")
    assert gg.git("add", "-A", cwd=repo).rc == 0        # the forged index, by git itself
    assert "160000" in gg.git("ls-files", "-s", cwd=repo).out
