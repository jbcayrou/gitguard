"""Nested repositories: the index gitlink is the barrier.

git opens a nested repository only once a gitlink references it; the
`git add -A` that creates the gitlink executes nothing (pytest version of the
proof in tests/nested_git_is_a_threat.sh), the next command is refused.
`.gitmodules` is read without walking the tree. The legitimate way out is a
real submodule (`git submodule absorbgitdirs`).
"""
from __future__ import annotations

import shutil
from pathlib import Path

from tests.conftest import GG, write_exec
from tests.test_attacks import assert_blocked_now


def plant_nested(gg: GG, repo: Path, mark: Path, evil: bool = True) -> Path:
    """The container: a nested repository with one commit and, if `evil`, a
    config/hooks that leave a trace if they execute."""
    sub = repo / "vendor"
    sub.mkdir()
    gg.git("init", "-q", cwd=sub)
    (sub / "v").write_text("v\n")
    gg.git("add", "v", cwd=sub)
    gg.git("commit", "-qm", "v", cwd=sub)
    if evil:
        gg.git("config", "core.fsmonitor", f"sh -c 'touch {mark}; exit 1'", cwd=sub)
        hooks = sub.parent.parent / "hooks"
        gg.git("config", "core.hooksPath", str(hooks), cwd=sub)
        for h in ("post-index-change", "pre-commit", "post-checkout"):
            write_exec(hooks / h, f"#!/bin/sh\ntouch {mark}\n")
    return sub


def test_first_add_does_not_execute(gg: GG, repo: Path, tmp_path: Path) -> None:
    """The assumption that makes the no-walk design acceptable: the `git add
    -A` that creates the gitlink does not execute the nested repository's
    config. Positive control afterwards: the next command, outside gitguard,
    does."""
    mark = tmp_path / "EXEC"
    plant_nested(gg, repo, mark)
    assert not gg.check(repo).blocked            # no gitlink: nothing to see
    for cmd in (["status", "--short"], ["diff"], ["stash", "-u"], ["clean", "-nd"]):
        assert gg.run("git", *cmd, cwd=repo).rc == 0, cmd
        assert not mark.exists(), f"git {' '.join(cmd)} executed the nested config"
    r = gg.run("git", "add", "-A", cwd=repo)
    assert r.rc == 0, r.text
    assert not mark.exists(), "the first `git add -A` executes the nested config: " \
                              "a tree walk before the add would be needed again"
    assert "160000" in gg.git("ls-files", "--stage", cwd=repo).out, "gitlink expected"
    assert_blocked_now(gg, repo, "nested repository")   # the next command refuses
    # Control: outside gitguard, git does execute from here on.
    gg.git("status", "--short", cwd=repo)
    assert mark.exists(), "invalid control: git no longer executes the nested config"


def test_nested_repo_repair(gg: GG, repo: Path, tmp_path: Path) -> None:
    """Documented repair: delete vendor/.git BEFORE `git rm --cached`."""
    sub = plant_nested(gg, repo, tmp_path / "EXEC")
    assert gg.run("git", "add", "-A", cwd=repo).rc == 0
    r = gg.check(repo)
    assert r.blocked and "vendor/.git" in r.err and "absorbgitdirs" in r.err, r.text
    assert "GITGUARD_PRUNE" not in r.err          # no longer a thing
    shutil.rmtree(sub / ".git")
    assert gg.run("git", "rm", "-qf", "--cached", "vendor", cwd=repo).rc == 0
    assert not gg.check(repo).blocked
    assert not (tmp_path / "EXEC").exists()


def test_vendored_repo_becomes_a_submodule(gg: GG, repo: Path, tmp_path: Path) -> None:
    """The legitimate way out named by the refusal: declare the directory in
    .gitmodules, `git submodule absorbgitdirs`, then trust."""
    plant_nested(gg, repo, tmp_path / "EXEC", evil=False)
    assert gg.run("git", "add", "-A", cwd=repo).rc == 0
    assert gg.check(repo).blocked
    (repo / ".gitmodules").write_text('[submodule "vendor"]\n\tpath = vendor\n\turl = ./vendor\n')
    assert gg.git("submodule", "absorbgitdirs", cwd=repo).rc == 0
    assert (repo / "vendor/.git").is_file()
    r = gg.run("trust", cwd=repo)
    assert r.rc == 0, r.text
    assert not gg.check(repo).blocked
    assert gg.run("git", "status", "--short", cwd=repo).rc == 0


def test_gitmodules_declared_planted_gitdir_still_refused(gg: GG, repo: Path) -> None:
    """[6] .gitmodules declares a directory whose .git is a planted directory:
    read without any tree walk, gitlink or not."""
    sub = repo / "build" / "x"
    sub.mkdir(parents=True)
    gg.git("init", "-q", cwd=sub)
    gg.git("config", "core.fsmonitor", "/tmp/evil", cwd=sub)
    (repo / ".gitmodules").write_text('[submodule "x"]\n\tpath = build/x\n\turl = ./x\n')
    assert gg.check(repo).blocked


def test_undeclared_nested_repo_without_gitlink_is_invisible(gg: GG, repo: Path) -> None:
    """No walk: a nested repository with no gitlink and no .gitmodules entry
    is not seen (git does not open it either); GITGUARD_SCAN_TREE no longer
    changes anything."""
    (repo / "vendor").mkdir()
    gg.git("init", "-q", cwd=repo / "vendor")
    assert not gg.check(repo).blocked
    gg.env["GITGUARD_SCAN_TREE"] = "1"
    assert not gg.check(repo).blocked
