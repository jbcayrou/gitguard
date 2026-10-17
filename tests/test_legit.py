"""Legitimate git operations: none may raise an alert (false-positive guard)."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from tests.attacks._helpers import add_submodule, make_source
from tests.conftest import GG


def commit(gg: GG, repo: Path, name: str = "f", content: str = "b") -> None:
    (repo / name).write_text(content + "\n")
    assert gg.git("add", name, cwd=repo).rc == 0
    assert gg.git("commit", "-qm", f"c-{name}-{content}", cwd=repo).rc == 0


def test_no_repo_passes(gg: GG, tmp_path: Path) -> None:
    assert not gg.check(tmp_path).blocked


def test_commit(gg: GG, repo: Path) -> None:
    commit(gg, repo)
    assert not gg.check(repo).blocked


def test_branch_tag_gc(gg: GG, repo: Path) -> None:
    gg.git("branch", "x", cwd=repo)
    gg.git("tag", "-a", "-m", "t", "v1", cwd=repo)
    gg.git("gc", "-q", cwd=repo)
    assert not gg.check(repo).blocked


def test_branch_named_like_watched_files(gg: GG, repo: Path) -> None:
    gg.git("branch", "config", cwd=repo)
    gg.git("branch", "hooks/x", cwd=repo)
    gg.git("commit", "-q", "--allow-empty", "-m", "e", cwd=repo)
    assert not gg.check(repo).blocked


def test_merge_checkout_fetch(gg: GG, repo: Path) -> None:
    commit(gg, repo)
    gg.git("checkout", "-qb", "br", cwd=repo)
    commit(gg, repo, "g", "x")
    gg.git("checkout", "-q", "main", cwd=repo)
    gg.git("merge", "-q", "--no-ff", "-m", "m", "br", cwd=repo)
    gg.git("fetch", "-q", ".", cwd=repo)
    assert not gg.check(repo).blocked


def test_stash(gg: GG, repo: Path) -> None:
    commit(gg, repo)
    (repo / "f").write_text("c\n")
    gg.git("stash", "-q", cwd=repo)
    gg.git("stash", "pop", "-q", cwd=repo)
    assert not gg.check(repo).blocked


def test_rebase_cherry_pick_revert(gg: GG, repo: Path) -> None:
    for i in range(3):
        commit(gg, repo, "g", str(i))
    gg.git("rebase", "-q", "HEAD~1", cwd=repo)
    gg.git("revert", "-q", "--no-edit", "HEAD", cwd=repo)
    assert not gg.check(repo).blocked


def test_bisect_in_progress(gg: GG, repo: Path) -> None:
    """BISECT_* present: excluded (and the glob was a bash trap)."""
    for i in range(3):
        commit(gg, repo, "g", str(i))
    gg.git("bisect", "start", "HEAD", "HEAD~2", cwd=repo)
    assert not gg.check(repo).blocked
    r = gg.run("diff", cwd=repo)
    assert "no changes" in r.err
    gg.git("bisect", "reset", cwd=repo)


def test_notes_repack_commit_graph(gg: GG, repo: Path) -> None:
    gg.git("notes", "add", "-m", "n", "HEAD", cwd=repo)
    gg.git("repack", "-adq", cwd=repo)
    gg.git("commit-graph", "write", cwd=repo)
    gg.git("reflog", "expire", "--all", cwd=repo)
    gg.git("prune", cwd=repo)
    assert not gg.check(repo).blocked


def test_worktree(gg: GG, repo: Path, tmp_path: Path) -> None:
    wt = tmp_path / "wt"
    assert gg.git("worktree", "add", "-q", str(wt), "-b", "wt", cwd=repo).rc == 0
    gg.trust(wt)
    assert not gg.check(wt).blocked
    commit(gg, wt)
    assert not gg.check(wt).blocked
    gg.trust(repo)
    (wt / "f").write_text("zz\n")
    gg.git("commit", "-qam", "c3", cwd=wt)
    assert not gg.check(repo).blocked, "commit in a worktree seen from the main repository"


def test_submodule_commit(gg: GG, repo: Path, tmp_path: Path) -> None:
    sub = add_submodule(gg, repo, tmp_path)
    gg.trust(repo)
    commit(gg, sub, "t", "t")
    assert not gg.check(repo).blocked


def test_hookspath_ordinary_commits(gg: GG, repo: Path) -> None:
    (repo / ".githooks").mkdir()
    gg.git("config", "core.hooksPath", ".githooks", cwd=repo)
    gg.trust(repo)
    commit(gg, repo)
    assert not gg.check(repo).blocked


def test_hookspath_system_readonly_ignored(gg: GG, repo: Path) -> None:
    gg.git("config", "core.hooksPath", "/usr/share/git-core/templates/hooks", cwd=repo)
    gg.trust(repo)
    assert not gg.check(repo).blocked


def test_hookspath_nonexistent_ignored(gg: GG, repo: Path) -> None:
    gg.git("config", "core.hooksPath", "/nonexistent/hooks", cwd=repo)
    gg.trust(repo)
    assert not gg.check(repo).blocked


def test_include_chain_unchanged(gg: GG, repo: Path) -> None:
    (repo / "level1").write_text("[include]\n\tpath = level2\n")
    (repo / "level2").write_text("[core]\n")
    gg.git("config", "include.path", "../level1", cwd=repo)
    gg.trust(repo)
    assert not gg.check(repo).blocked


def test_nested_repo_refused_with_prune_escape_hatch(gg: GG, repo: Path) -> None:
    """With the tree scan, a nested repository is refused as soon as it appears
    (RCE via gitlink, see tests/nested_git_is_a_threat.sh); GITGUARD_PRUNE is
    the escape hatch."""
    gg.env["GITGUARD_SCAN_TREE"] = "1"
    (repo / "vendor").mkdir()
    gg.git("init", "-q", cwd=repo / "vendor")
    r = gg.check(repo)
    assert r.blocked and "GITGUARD_PRUNE" in r.err
    gg.env["GITGUARD_PRUNE"] = "vendor"
    assert not gg.check(repo).blocked


def test_vendored_repo_prune_still_works(gg: GG, repo: Path) -> None:
    gg.env["GITGUARD_SCAN_TREE"] = "1"
    (repo / "vendor").mkdir()
    gg.git("init", "-q", cwd=repo / "vendor")
    gg.env["GITGUARD_PRUNE"] = "vendor"
    assert not gg.check(repo).blocked


def test_node_modules_pruned(gg: GG, repo: Path) -> None:
    gg.env["GITGUARD_SCAN_TREE"] = "1"
    (repo / "node_modules").mkdir()
    gg.git("init", "-q", cwd=repo / "node_modules")
    assert not gg.check(repo).blocked


def test_access_through_symlinked_path(gg: GG, repo: Path, tmp_path: Path) -> None:
    os.symlink(repo, tmp_path / "link")
    assert not gg.check(tmp_path / "link").blocked, "same key through a symlinked path"


def test_recurse_submodules_clone(gg: GG, repo: Path, tmp_path: Path) -> None:
    add_submodule(gg, repo, tmp_path)
    dst = tmp_path / "superclone"
    r = gg.run("git", "-c", "protocol.file.allow=always", "clone", "-q",
               "--recurse-submodules", str(repo), str(dst), cwd=tmp_path)
    assert r.rc == 0, r.text
    assert not gg.check(dst).blocked, "gitfiles under .git/modules → auto-trust OK"
    commit(gg, dst / "sub", "t", "t")
    assert not gg.check(dst).blocked


def test_hookspath_symlink_to_tree_script_unchanged(gg, repo, tmp_path):
    """hooksPath hook = symlink to a tree script: legitimate as long as neither
    the link nor the target changes (ordinary commits afterwards)."""
    import os
    from tests.conftest import write_exec
    write_exec(repo / "scripts/hook.sh", "#!/bin/sh\nexit 0\n")
    (repo / ".githooks").mkdir()
    os.symlink("../scripts/hook.sh", repo / ".githooks/pre-commit")
    gg.git("config", "core.hooksPath", ".githooks", cwd=repo)
    gg.trust(repo)
    (repo / "f").write_text("b\n")
    gg.git("add", "-A", cwd=repo)
    assert gg.git("commit", "-qm", "c", cwd=repo).rc == 0
    r = gg.check(repo)
    assert not r.blocked, r.text


def test_vanished_or_unreadable_object_dir_is_not_a_refusal(gg: GG, repo: Path) -> None:
    """A detached `git gc --auto` removes `objects/xx` directories during the
    walk: gitguard used to refuse ("unreadable directory"). Objects are
    volatile and not executable: the scan must not even descend there."""
    d = repo / ".git/objects/ab"
    d.mkdir(exist_ok=True)
    (d / "x").write_text("")
    d.chmod(0)                           # simulates scandir failing on this directory
    try:
        r = gg.check(repo)
        assert not r.blocked, r.text
    finally:
        d.chmod(0o755)


def test_dir_only_marker_head_file_is_not_a_gitdir(gg: GG, repo: Path) -> None:
    """[23] a directory that only contains a HEAD file is not a gitdir."""
    (repo / "docs").mkdir()
    (repo / "docs/HEAD").write_text("x\n")
    assert not gg.check(repo).blocked


def test_safe_directory_global_does_not_watch_siblings(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[25] safe.directory to the repository's parent: a directory is not an
    executed file, it must not enter the fingerprint."""
    gg.git("config", "--global", "safe.directory", str(tmp_path))
    r = gg.trust(repo)
    assert "ext:" not in r.err, r.err
    (tmp_path / "sibling").mkdir()
    (tmp_path / "sibling/new").write_text("x\n")
    assert not gg.check(repo).blocked


def test_local_remote_commits_do_not_alert(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[25] remote.origin.url = local repository: commits over there, no alert
    here. Only its config and hooks/ are watched [45], never the directory."""
    other = make_source(gg, tmp_path, "other")
    gg.git("remote", "add", "origin", str(other), cwd=repo)
    r = gg.trust(repo)
    o = other.resolve()
    ext = {t[4:] for t in r.err.split() if t.startswith("ext:")}
    assert ext == {f"{o}/.git/config", f"{o}/.git/hooks"}, r.err
    (other / "b").write_text("b\n")
    gg.git("add", "b", cwd=other)
    gg.git("commit", "-qm", "b", cwd=other)
    assert not gg.check(repo).blocked


def test_alias_with_directory_argument(gg: GG, repo: Path) -> None:
    """[25] alias = !make -C src: src/ does not enter the fingerprint."""
    (repo / "src").mkdir()
    (repo / "src/a.c").write_text("")
    gg.git("config", "alias.b", "!make -C src", cwd=repo)
    r = gg.trust(repo)
    assert "wt:" not in r.err, r.err
    (repo / "src/b.c").write_text("")
    assert not gg.check(repo).blocked


def test_submodule_gc_and_update_server_info(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[26] gc / update-server-info in a submodule: info/refs,
    objects/info/packs and commit-graph are volatile under modules/ too."""
    sub = add_submodule(gg, repo, tmp_path)
    gg.trust(repo)
    commit(gg, sub, "t", "t")
    assert gg.git("gc", "-q", cwd=sub).rc == 0
    assert gg.git("update-server-info", cwd=sub).rc == 0
    assert gg.git("commit-graph", "write", cwd=sub).rc == 0
    r = gg.check(repo)
    assert not r.blocked, r.text


def test_worktree_inside_main_tree(gg: GG, repo: Path) -> None:
    """[27] git worktree add .worktrees/wt: gitfile to .git/worktrees/, legitimate."""
    assert gg.git("worktree", "add", "-q", ".worktrees/wt", "-b", "wt", cwd=repo).rc == 0
    gg.trust(repo)
    assert not gg.check(repo).blocked
    commit(gg, repo / ".worktrees/wt", "g", "g")
    assert not gg.check(repo).blocked


def test_nested_submodule_and_slashed_name_still_anchored(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[29] roots are only recognised under modules/ and worktrees/: a submodule
    named lib/foo (modules/lib/foo) must remain a root (otherwise its
    refs/logs alert on every commit)."""
    sub = add_submodule(gg, repo, tmp_path, "lib/foo")
    gg.trust(repo)
    commit(gg, sub, "t", "t")
    assert gg.git("gc", "-q", cwd=sub).rc == 0
    r = gg.check(repo)
    assert not r.blocked, r.text


def test_push_fetch_local_remote_no_alert(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[45] a local remote's config and hooks/ are watched: an ordinary push
    and fetch to/from it must not alert."""
    bare = tmp_path / "remote.git"
    assert gg.git("init", "-q", "--bare", str(bare)).rc == 0
    gg.git("remote", "add", "origin", str(bare), cwd=repo)
    gg.trust(repo)
    for args in (["push", "-q", "origin", "HEAD:refs/heads/main"], ["fetch", "-q", "origin"],
                 ["push", "-q", "origin", "HEAD:refs/heads/other"]):
        r = gg.run("git", *args, cwd=repo)
        assert r.rc == 0, r.text
    assert not gg.check(repo).blocked, gg.check(repo).text


def test_remote_of_remote_not_followed(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[45] pushing to A does not push to A's remotes: A's own remotes are not
    pulled into the fingerprint."""
    far = tmp_path / "far.git"
    near = tmp_path / "near.git"
    gg.git("init", "-q", "--bare", str(far))
    gg.git("init", "-q", "--bare", str(near))
    gg.git("--git-dir", str(near), "remote", "add", "up", str(far))
    gg.git("remote", "add", "origin", str(near), cwd=repo)
    gg.trust(repo)
    (far / "hooks/pre-receive").write_text("#!/bin/sh\n")
    assert not gg.check(repo).blocked
