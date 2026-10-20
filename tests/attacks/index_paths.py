"""Index entry names that escape the work tree. [55]

git validates a path (verify_path: no `.git` component in any case, no `.`,
`..` or empty component, not absolute) when it reads a tree into the index,
not when it writes a file from the index: `checkout -- .`, `restore
--worktree` and `checkout-index` write a forged `.git/index` entry as is.
The index is volatile (outside the fingerprint) and the hook lands after the
check: `post-checkout` is written then run by the same command. Oracles in
tests/test_git_parity.py (section 9).
"""
from __future__ import annotations

from pathlib import Path

from tests.attacks._helpers import INDEX_ESCAPES, add_submodule, forge_index
from tests.conftest import GG

HOOK = b"#!/bin/sh\ntouch /tmp/evil\n"


def _forge(gg: GG, repo: Path, variant: str) -> None:
    forge_index(gg, repo, [(0o100755, HOOK, INDEX_ESCAPES[variant][0])])


def attack_index_name_into_gitdir(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[55] index entry `.git/hooks/post-checkout`: written then run by checkout -- ."""
    _forge(gg, repo, "into_gitdir")


def attack_index_name_dotgit_case(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[55] index entry `.GIT/hooks/…`: the same directory on a case-insensitive filesystem"""
    _forge(gg, repo, "dotgit_case")


def attack_index_name_dot_component(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[55] index entry `./.git/hooks/…`"""
    _forge(gg, repo, "dot_component")


def attack_index_name_dotdot_inside(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[55] index entry `x/../.git/hooks/…`"""
    _forge(gg, repo, "dotdot_inside")


def attack_index_name_empty_component(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[55] index entry `x//../.git/hooks/…`"""
    _forge(gg, repo, "empty_component")


def attack_index_name_dotdot_out(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[55] index entry `../escaped`: written outside the repository"""
    _forge(gg, repo, "dotdot_out")


def attack_index_name_absolute(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[55] absolute index entry name: written at that path, anywhere"""
    forge_index(gg, repo, [(0o100644, b"x\n", str(tmp_path.resolve() / "abs-escaped").encode())])


def attack_index_submodule_escape(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[55] submodule index (.git/modules/sub/index) with `../.git/hooks/…`:
    an unwrapped `submodule foreach git checkout -- .` writes the
    superproject's hook"""
    sub = add_submodule(gg, repo, tmp_path)
    gg.trust(repo)
    forge_index(gg, sub, [(0o100755, HOOK, b"../.git/hooks/post-checkout")],
                gitdir=repo / ".git/modules/sub")
