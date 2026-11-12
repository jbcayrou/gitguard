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

import pytest

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
    .gitmodules, `git submodule absorbgitdirs` — through gitguard since
    [149], the `.gitmodules` just written trusted first — then trust."""
    plant_nested(gg, repo, tmp_path / "EXEC", evil=False)
    assert gg.run("git", "add", "-A", cwd=repo).rc == 0
    assert gg.check(repo).blocked
    (repo / ".gitmodules").write_text('[submodule "vendor"]\n\tpath = vendor\n\turl = ./vendor\n')
    r = gg.run("git", "submodule", "absorbgitdirs", cwd=repo)
    assert r.blocked and "has changed" in r.err and "nested repository" not in r.err, r.text
    from tests.test_prompt import run_with_tty
    rc, _, tty = run_with_tty(gg, ["git", "submodule", "absorbgitdirs"], repo, "y")
    assert rc == 0, tty
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


# ---------------------------------------------- [154] what a tree does not inherit
# A submodule or a linked worktree takes the trust of the repository whose
# `.git` holds its gitdir when that repository is in its trusted state and
# every file the tree's own check watches is in its reference. Each test is
# one way of not being there: the tree stays "never trusted".
def _sub(gg: GG, repo: Path, tmp_path: Path) -> Path:
    from tests.attacks._helpers import add_submodule
    sub = add_submodule(gg, repo, tmp_path)
    gg.trust(repo)
    return sub


def _refused(gg: GG, tree: Path) -> None:
    r = gg.run("git", "status", "--short", cwd=tree)
    assert r.blocked and "never trusted" in r.err and "trusted with" not in r.err, r.text
    assert not gg.key_for(tree).is_file()


def test_no_inheritance_from_a_changed_superproject(gg: GG, repo: Path, tmp_path: Path) -> None:
    """The sandbox rewrites the submodule's config after the trust: the
    superproject is not in its trusted state, nothing is inherited — the
    diff is the superproject's to show."""
    sub = _sub(gg, repo, tmp_path)
    gg.git("config", "core.pager", "sh evil.sh", cwd=sub)
    _refused(gg, sub)
    r = gg.check(repo)
    assert r.blocked and "modules/sub/config" in r.err, r.text


def test_no_inheritance_when_a_named_file_went_missing(gg: GG, repo: Path, tmp_path: Path) -> None:
    """A file the submodule's config names in its tree is gone: nothing of
    the submodule's own fingerprint differs from the reference (one entry
    less), the superproject's does."""
    from tests.attacks._helpers import add_submodule
    sub = add_submodule(gg, repo, tmp_path)
    gg.git("config", "core.hooksPath", ".hk", cwd=sub)
    write_exec(sub / ".hk/pre-push", "#!/bin/sh\nexit 0\n")
    gg.trust(repo)
    (sub / ".hk/pre-push").unlink()
    _refused(gg, sub)


def test_no_inheritance_from_a_superproject_never_trusted(gg: GG, repo: Path, tmp_path: Path) -> None:
    sub = _sub(gg, repo, tmp_path)
    assert gg.run("forget", str(repo)).rc == 0
    _refused(gg, sub)


def test_no_inheritance_under_a_redirecting_environment(gg: GG, repo: Path, tmp_path: Path) -> None:
    """`GIT_WORK_TREE`, `GIT_DIR`…: the tree git works in is not the one
    the gitdir names; judged by hand, as before ([72])."""
    sub = _sub(gg, repo, tmp_path)
    other = tmp_path / "other"
    other.mkdir()
    gg.env["GIT_WORK_TREE"] = str(other)
    r = gg.run("git", "status", "--short", cwd=sub)
    assert r.blocked and "never trusted" in r.err, r.text


def test_no_inheritance_for_a_worktree_the_main_tree_has_not_seen(gg: GG, repo: Path,
                                                                 tmp_path: Path) -> None:
    """`worktree add` by something gitguard did not run: its `worktrees/<id>`
    is not in the main tree's reference yet."""
    wt = tmp_path / "wt"
    assert gg.git("worktree", "add", "-q", str(wt), cwd=repo).rc == 0
    _refused(gg, wt)


def test_no_inheritance_when_the_worktree_hook_differs(gg: GG, repo: Path, tmp_path: Path) -> None:
    """A relative `core.hooksPath` resolves in the worktree's own tree
    ([120]): another branch's hooks, or the sandbox's, were shown to
    nobody."""
    gg.git("config", "core.hooksPath", ".githooks", cwd=repo)
    write_exec(repo / ".githooks/pre-commit", "#!/bin/sh\nexit 0\n")
    gg.git("add", "-A", cwd=repo)
    gg.git("commit", "-qm", "hooks", cwd=repo)
    wt = tmp_path / "wt"
    assert gg.git("worktree", "add", "-q", str(wt), cwd=repo).rc == 0
    gg.trust(repo)
    write_exec(wt / ".githooks/pre-commit", "#!/bin/sh\necho other\n")
    _refused(gg, wt)
    write_exec(wt / ".githooks/pre-commit", "#!/bin/sh\nexit 0\n")
    write_exec(wt / ".githooks/post-checkout", "#!/bin/sh\necho new\n")
    _refused(gg, wt)


# ------------------------------- [155] what a `git worktree` command does not get accepted
def _hooked_add(gg: GG, repo: Path, tmp_path: Path, hook: str) -> Path:
    """`worktree add` through gitguard while something else writes into the
    gitdir: a trusted post-checkout hook stands for the sandbox, running in
    the new worktree before the command returns."""
    write_exec(repo / ".git/hooks/post-checkout", "#!/bin/sh\n" + hook)
    gg.trust(repo)
    wt = tmp_path / "wt"
    r = gg.run("git", "worktree", "add", "-q", str(wt), cwd=repo)
    assert r.rc == 0 and "reference updated" not in r.err, r.text
    return wt


def test_worktree_add_accepts_nothing_else_written_meanwhile(gg: GG, repo: Path, tmp_path: Path) -> None:
    """Another file of the gitdir changed during the command: nothing is
    accepted, the next command shows the pointers and the rest."""
    wt = _hooked_add(gg, repo, tmp_path, f"echo '#!/bin/sh' > '{repo}/.git/hooks/pre-commit'\n")
    r = gg.check(repo)
    assert r.blocked and "hooks/pre-commit" in r.err and "worktrees/wt/gitdir" in r.err, r.text
    assert gg.run("git", "status", "--short", cwd=wt).blocked


def test_worktree_add_accepts_one_worktree(gg: GG, repo: Path, tmp_path: Path) -> None:
    """A second worktree planted during the command, pointers and gitfile
    consistent: `add` writes one."""
    adm = repo / ".git/worktrees/evil"
    _hooked_add(gg, repo, tmp_path,
                f"mkdir -p '{adm}' '{repo}/src' && echo 'ref: refs/heads/main' > '{adm}/HEAD' && "
                f"echo ../.. > '{adm}/commondir' && echo '{repo}/src/.git' > '{adm}/gitdir' && "
                f"echo 'gitdir: {adm}' > '{repo}/src/.git'\n")
    r = gg.check(repo)
    assert r.blocked and "worktrees/evil/gitdir" in r.err, r.text
    assert gg.run("git", "status", "--short", cwd=repo / "src").blocked


@pytest.mark.parametrize("pointer, content", [
    ("gitdir", "{repo}/src/.git"),             # a tree whose gitfile does not point back
    ("gitdir", "{repo}/src"),                  # not a `.git`
    ("gitdir", "../../../../wt/.git"),         # relative: not what git writes without the extension
    ("commondir", "../../"),                   # git reads the same directory; not git's bytes
    ("commondir", "{repo}/.git"),
])
def test_worktree_add_accepts_only_what_git_writes(gg: GG, repo: Path, tmp_path: Path,
                                                   pointer: str, content: str) -> None:
    """The pointers of the new worktree rewritten during the command."""
    (repo / "src").mkdir()
    value = content.format(repo=repo)
    _hooked_add(gg, repo, tmp_path, f"printf '%s\\n' '{value}' > '{repo}/.git/worktrees/wt/{pointer}'\n")
    r = gg.check(repo)
    assert r.blocked and "worktrees/wt/gitdir" in r.err, r.text


def test_worktree_command_on_a_changed_repository_is_asked_first(gg: GG, repo: Path, tmp_path: Path) -> None:
    """Not in its trusted state: the command does not run, as any other."""
    write_exec(repo / ".git/hooks/pre-commit")
    r = gg.run("git", "worktree", "add", "-q", str(tmp_path / "wt"), cwd=repo)
    assert r.blocked and not (tmp_path / "wt").exists(), r.text


def test_worktree_add_by_another_git_is_still_asked(gg: GG, repo: Path, tmp_path: Path) -> None:
    """The same pointers, written by a git gitguard did not run (the
    sandbox's, an IDE's bundled one): shown, asked."""
    assert gg.git("worktree", "add", "-q", str(tmp_path / "wt"), cwd=repo).rc == 0
    r = gg.run("git", "status", "--short", cwd=repo)
    assert r.blocked and "worktrees/wt/commondir" in r.err, r.text


def test_worktree_add_from_a_linked_worktree_is_still_asked(gg: GG, repo: Path, tmp_path: Path) -> None:
    """Run from a linked worktree, the pointers land in the main
    repository's gitdir, under two references (this worktree's, the main
    tree's): left to the next command of each."""
    w1 = tmp_path / "w1"
    assert gg.run("git", "worktree", "add", "-q", str(w1), cwd=repo).rc == 0
    assert gg.run("git", "status", "--short", cwd=w1).rc == 0
    r = gg.run("git", "worktree", "add", "-q", str(tmp_path / "w2"), cwd=w1)
    assert r.rc == 0 and "reference updated" not in r.err, r.text
    assert gg.check(repo).blocked and gg.check(w1).blocked
