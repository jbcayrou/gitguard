"""Legitimate git operations: none may raise an alert (false-positive guard)."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from tests.attacks._helpers import add_submodule, make_source
from tests.conftest import GG, write_exec


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


def test_rebase_builtin_strategy_in_progress(gg: GG, repo: Path) -> None:
    """An interrupted rebase that recorded a builtin `strategy` (`-s resolve`)
    must not alert: only a non-builtin name is an exec vector. [51]"""
    import shlex, subprocess, sys
    for i in range(3):
        commit(gg, repo, "g", str(i))
    editor = repo.parent / "seq-editor.py"
    editor.write_text("import sys\np = sys.argv[1]\nl = open(p).read().split('\\n')\n"
                      "l.insert(1, 'break')\nopen(p, 'w').write('\\n'.join(l))\n")
    env = dict(gg.env, GIT_SEQUENCE_EDITOR=f"{shlex.quote(sys.executable)} {shlex.quote(str(editor))}")
    subprocess.run(["git", "rebase", "-i", "-s", "resolve", "HEAD~2"], cwd=repo,
                   env=env, capture_output=True, text=True)
    strat = repo / ".git/rebase-merge/strategy"
    assert strat.is_file() and strat.read_text().strip() == "resolve"
    gg.trust(repo)
    assert not gg.check(repo).blocked


def test_cherry_pick_builtin_strategy_in_progress(gg: GG, repo: Path) -> None:
    """A stopped `cherry-pick --strategy=recursive` keeps `strategy = recursive`
    in sequencer/opts: builtin, must not alert. [51]"""
    from tests.attacks.tool_itself import _interrupted_cherry_pick
    opts = _interrupted_cherry_pick(gg, repo)
    assert "strategy = recursive" in opts.read_text()
    gg.trust(repo)
    assert not gg.check(repo).blocked


def test_bisect_in_progress(gg: GG, repo: Path) -> None:
    """BISECT_* present: excluded (and the glob was a bash trap)."""
    for i in range(3):
        commit(gg, repo, "g", str(i))
    gg.git("bisect", "start", "HEAD", "HEAD~2", cwd=repo)
    assert not gg.check(repo).blocked
    r = gg.run("diff", cwd=repo)
    assert "no changes" in r.out
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
    assert "ext:" not in r.out, r.out
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
    refs = [l for l in r.out.splitlines() if "references outside the gitdir" in l]   # not the diff
    ext = {t[4:] for t in refs[0].split() if t.startswith("ext:")}
    assert ext == {f"{o}/.git/config", f"{o}/.git/hooks"}, r.out
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
    assert "wt:" not in r.out, r.out
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


def test_env_index_file_scratch_index(gg: GG, repo: Path, tmp_path: Path) -> None:
    """A script's scratch index (`GIT_INDEX_FILE=tmp git add … && git
    write-tree`, pre-commit's stash dance): read like git reads it, no
    alert when it holds no gitlink; the gitdir's index is untouched. [54]"""
    (repo / "g").write_text("g\n")
    gg.env["GIT_INDEX_FILE"] = str(tmp_path / "scratch.idx")
    assert gg.git("read-tree", "HEAD", cwd=repo).rc == 0
    assert gg.git("add", "g", cwd=repo).rc == 0
    assert gg.git("write-tree", cwd=repo).rc == 0
    assert not gg.check(repo).blocked
    assert not gg.run("git", "status", cwd=repo).blocked
    gg.env["GIT_INDEX_FILE"] = "scratch-in-tree.idx"               # relative to the root
    assert gg.git("add", "g", cwd=repo).rc == 0
    assert not gg.check(repo).blocked
    del gg.env["GIT_INDEX_FILE"]
    assert not gg.check(repo).blocked


def test_env_common_dir_own_gitdir(gg: GG, repo: Path, tmp_path: Path) -> None:
    """GIT_COMMON_DIR naming the repository's own gitdir, or the main
    repository from its linked worktree: the same files, no alert. [54]"""
    gg.env["GIT_COMMON_DIR"] = str(repo / ".git")
    assert not gg.check(repo).blocked
    assert not gg.run("git", "status", cwd=repo).blocked
    del gg.env["GIT_COMMON_DIR"]
    assert gg.git("worktree", "add", "-q", str(tmp_path / "wt"), cwd=repo).rc == 0
    gg.trust(tmp_path / "wt")                      # a linked worktree has its own key
    assert not gg.check(tmp_path / "wt").blocked
    gg.env["GIT_COMMON_DIR"] = str(repo / ".git")  # what its commondir file already says
    assert not gg.check(tmp_path / "wt").blocked
    assert not gg.run("git", "status", cwd=tmp_path / "wt").blocked


@pytest.mark.parametrize("name", [".github/workflows/ci.yml", ".gitignore", ".gitattributes",
                                  "dir/.gitkeep", "a.git/x", "x.git", "..x", "x..", "...",
                                  ".git-blame-ignore-revs", "d/.gitmodules-like", "g.it/x"])
def test_index_names_close_to_git_rules(gg: GG, repo: Path, name: str) -> None:
    """Names git accepts in an index, next to the ones [55] must refuse
    (`.git`, `.`, `..`, empty, absolute): no alert, through the wrapper too."""
    p = repo / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("x\n")
    assert gg.git("add", name, cwd=repo).rc == 0
    assert gg.git("commit", "-qm", name, cwd=repo).rc == 0
    assert not gg.check(repo).blocked
    assert not gg.run("git", "checkout", "--", ".", cwd=repo).blocked


def test_global_config_change_without_a_path_is_silent(gg: GG, repo: Path) -> None:
    """[56] The global config is parsed for the paths it names, never hashed:
    whoever can write ~/.gitconfig can write the state directory, and every
    `git config --global` / `git lfs install` turned every repository
    "modified" at once."""
    for k, v in [("user.email", "x@y"), ("alias.st", "status"),
                 ("filter.lfs.clean", "git-lfs clean -- %f"), ("filter.lfs.smudge", "git-lfs smudge -- %f"),
                 ("filter.lfs.process", "git-lfs filter-process"), ("filter.lfs.required", "true")]:
        assert gg.git("config", "--global", k, v).rc == 0
    assert not gg.check(repo).blocked
    assert not gg.run("git", "status", cwd=repo).blocked
    assert "ok" in gg.run("list").out and "modified" not in gg.run("list").out
    assert not (gg.key_for(repo).with_name(gg.key_for(repo).name + ".d") / "global").exists()


@pytest.mark.parametrize("key, extra", [
    ("user.signingKey", ("gpg.format", "ssh")),
    ("gpg.ssh.allowedSignersFile", None),
    ("commit.template", None),
    ("core.excludesFile", None),
    ("http.https://x.example.sslKey", None),
])
def test_data_key_file_rotation_is_silent(gg: GG, repo: Path, tmp_path: Path, key: str, extra) -> None:
    """[56] A file git reads as data (DATA_KEYS: a signing key, a template, an
    excludes file…) is not watched: rewriting it — a key rotation — is not a
    change of the repository, and a private key is never copied into the
    state directory."""
    f = tmp_path / "home" / "datafile"
    f.write_text("SECRET\n")
    f.chmod(0o600)
    if extra:
        assert gg.git("config", "--global", *extra).rc == 0
    assert gg.git("config", "--global", key, str(f)).rc == 0
    r = gg.trust(repo)
    assert "ext:" not in r.text, r.text
    bak = gg.key_for(repo).with_name(gg.key_for(repo).name + ".d")
    assert not any(p.name == "datafile" for p in bak.rglob("*")), "the data file was copied"
    f.write_text("ROTATED\n")
    assert not gg.check(repo).blocked
    assert not gg.run("git", "status", cwd=repo).blocked


# ------------------------------- false positives [63] [64] [65]
def test_sha256_repository_can_be_trusted(gg: GG, tmp_path: Path) -> None:
    """[63] `git init --object-format=sha256`: the index entries hold 32-byte
    object ids, the parser assumed 20 and refused the index as forged."""
    r = tmp_path / "s256"
    assert gg.git("init", "-q", "--object-format=sha256", str(r)).rc == 0
    commit(gg, r)
    gg.trust(r)
    commit(gg, r, "g", "x")
    assert not gg.check(r).blocked


def test_reftable_commit_and_branch(gg: GG, tmp_path: Path) -> None:
    """[64] `git init --ref-format=reftable`: every ref update rewrites
    `reftable/tables.list` and the tables, which were fingerprinted."""
    r = tmp_path / "rt"
    assert gg.git("init", "-q", "--ref-format=reftable", str(r)).rc == 0
    commit(gg, r)
    gg.trust(r)
    commit(gg, r, "g", "x")
    gg.git("branch", "b2", cwd=r)
    assert not gg.check(r).blocked, gg.run("diff", cwd=r).text


def test_hookspath_above_the_state_directory(gg: GG, repo: Path) -> None:
    """[65] core.hooksPath = .. with the state directory under that parent
    (here `tmp_path/state`; in real life `~/.local/state/gitguard` under a
    hooksPath of `~`): the manifest that `trust` writes is itself watched, so
    the repository alerts again right after every `trust`."""
    gg.git("config", "core.hooksPath", "..", cwd=repo)
    gg.trust(repo)
    assert not gg.check(repo).blocked, gg.run("diff", cwd=repo).text


def test_hookspath_above_the_tree_ignores_tree_edits(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[65] core.hooksPath = .. with the state directory elsewhere:
    git runs only `../<hook>`, yet editing a tracked file of the repository
    alerts (the parent is walked recursively, the tree included)."""
    import tempfile
    gg.env["GITGUARD_STATE"] = tempfile.mkdtemp(dir=tmp_path.parent)
    gg.git("config", "core.hooksPath", "..", cwd=repo)
    gg.trust(repo)
    commit(gg, repo)
    assert not gg.check(repo).blocked, gg.run("diff", cwd=repo).text


def test_nested_submodules_recursive(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[60] a submodule with its own submodule (`--recursive`): the inner
    gitfile points under `.git/modules/<sub>/modules/`, nothing alerts —
    after the clone, a commit in the inner one and a superproject status."""
    inner_src = make_source(gg, tmp_path, "innersrc")
    mid = make_source(gg, tmp_path, "midsrc")
    assert gg.git("submodule", "add", "-q", str(inner_src), "inner", cwd=mid).rc == 0
    assert gg.git("commit", "-qm", "inner", cwd=mid).rc == 0
    assert gg.git("submodule", "add", "-q", str(mid), "mid", cwd=repo).rc == 0
    assert gg.git("submodule", "update", "-q", "--init", "--recursive", cwd=repo).rc == 0
    assert gg.git("commit", "-qm", "mid", cwd=repo).rc == 0
    g = (repo / "mid/inner/.git").read_text()
    assert "modules/mid/modules/inner" in g, g
    gg.trust(repo)
    commit(gg, repo / "mid/inner", "t", "t")
    assert gg.run("git", "status", cwd=repo).rc == 0
    r = gg.check(repo)
    assert not r.blocked, r.text


def test_sha256_submodule_in_sha1_superproject(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[63] each gitdir has its own object format: a SHA-256 submodule's
    index is read with 32-byte ids, the superproject's with 20."""
    src = tmp_path / "s256src"
    assert gg.git("init", "-q", "--object-format=sha256", str(src)).rc == 0
    commit(gg, src)
    r = gg.git("submodule", "add", "-q", str(src), "sub", cwd=repo)
    if r.rc:
        pytest.skip(f"this git refuses mixed object formats: {r.err.strip()}")
    gg.git("commit", "-qm", "sub", cwd=repo)
    gg.trust(repo)
    assert not gg.check(repo).blocked


def test_sha256_submodule_with_a_linked_worktree(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[63] the index of a submodule's linked worktree
    (`modules/<x>/worktrees/<w>/index`) has the submodule's object format,
    found through its `commondir`, not the superproject's."""
    src = tmp_path / "s256src"
    assert gg.git("init", "-q", "--object-format=sha256", str(src)).rc == 0
    commit(gg, src)
    r = gg.git("submodule", "add", "-q", str(src), "sub", cwd=repo)
    if r.rc:
        pytest.skip(f"this git refuses mixed object formats: {r.err.strip()}")
    gg.git("commit", "-qm", "sub", cwd=repo)
    assert gg.git("worktree", "add", "-q", str(tmp_path / "subwt"), cwd=repo / "sub").rc == 0
    assert (repo / ".git/modules/sub/worktrees").is_dir()
    gg.trust(repo)
    assert not gg.check(repo).blocked, gg.check(repo).text


# ---------------------------------------- adversarial review of 2026-10-22
def test_global_program_path_that_is_a_symlink(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[75] `gpg.program = /opt/homebrew/bin/gpg` (Homebrew symlinks
    every binary), `core.editor = /usr/bin/vim` (Debian alternatives), a
    stow-managed `~/.gitconfig.local`: add() refuses any config path that is
    itself a symlink, so every repository is refused, `trust` included."""
    real = tmp_path / "opt/Cellar/gpg/bin/gpg"
    write_exec(real, "#!/bin/sh\nexit 0\n")
    link = tmp_path / "opt/bin/gpg"
    link.parent.mkdir(parents=True)
    link.symlink_to(real)
    gg.git("config", "--global", "gpg.program", str(link))
    r = gg.run("trust", cwd=repo)
    assert r.rc == 0, r.text
    assert not gg.check(repo).blocked


def test_global_program_path_that_is_a_hard_link(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[88] `gpg.program = /opt/homebrew/bin/gpg` where the binary has other
    names (Homebrew's Cellar hard-links some, on the same volume as $HOME
    on macOS), a hard-linked dotfile: the hard-link refusal covers the tree
    and the gitdir only — the sandbox can link nothing else — so a program
    named outside them is watched by its bytes, never refused."""
    real = tmp_path / "opt/Cellar/gpg/bin/gpg"
    write_exec(real, "#!/bin/sh\nexit 0\n")
    other = tmp_path / "opt/Cellar/gpg/bin/gpg2"
    os.link(real, other)
    link = tmp_path / "opt/bin/gpg"           # Homebrew's symlink to the Cellar
    link.parent.mkdir(parents=True)
    link.symlink_to(real)
    for prog in (real, link):
        gg.git("config", "--global", "gpg.program", str(prog))
        r = gg.run("trust", cwd=repo)
        assert r.rc == 0, r.text
        assert not gg.check(repo).blocked, gg.check(repo).text


def test_linked_worktree_of_a_submodule(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[76] `git -C sub worktree add ../subwt`: git ignores the
    common config's core.worktree in a linked worktree; open_repo applied
    it and took `.git/modules/sub` for the tree (a volatile-zone refusal,
    or an internal ValueError)."""
    add_submodule(gg, repo, tmp_path)
    wt = tmp_path / "subwt"
    assert gg.git("worktree", "add", "-q", str(wt), cwd=repo / "sub").rc == 0
    top = gg.git("rev-parse", "--show-toplevel", cwd=wt).out.strip()
    assert Path(top).resolve() == wt.resolve()
    r = gg.run("trust", cwd=wt)
    assert r.rc == 0, r.text
    assert not gg.run("git", "status", cwd=wt).blocked


def test_global_relative_hookspath_with_remote_and_submodule_is_quiet(gg: GG, repo: Path,
                                                                       tmp_path: Path) -> None:
    """[68] a global `core.hooksPath = .githooks` resolved in a local remote
    and in a submodule too: with the directories absent, or present and
    unchanged, nothing is reported."""
    from tests.attacks._helpers import add_submodule
    hub = tmp_path / "hub.git"
    gg.git("init", "-q", "--bare", str(hub))
    gg.git("remote", "add", "hub", str(hub), cwd=repo)
    sub = add_submodule(gg, repo, tmp_path)
    gg.git("config", "--global", "core.hooksPath", ".githooks")
    gg.trust(repo)
    assert not gg.check(repo).blocked
    for d in (repo, hub, sub):
        write_exec(d / ".githooks/pre-commit", "#!/bin/sh\nexit 0\n")
    gg.trust(repo)
    assert not gg.check(repo).blocked
    assert not gg.run("git", "status", cwd=repo).blocked


def test_checkout_summary_still_reports_a_submodule(gg: GG, repo: Path, subsrc: Path) -> None:
    """[66] a real submodule: the `git status --porcelain=2` git runs in it
    is gitguard, covered by the superproject's judgment (its gitdir is
    under `modules/`): the summary of local changes names the submodule
    with new commits and modified content, as the real git does."""
    assert gg.git("submodule", "add", "-q", str(subsrc), "sub", cwd=repo).rc == 0
    gg.git("commit", "-qm", "sub", cwd=repo)
    gg.trust(repo)
    gg.git("checkout", "-qb", "other", cwd=repo)
    # new commit in the submodule, and a dirty file there
    (repo / "sub/t").write_text("t\n")
    gg.git("add", "t", cwd=repo / "sub")
    gg.git("commit", "-qm", "t", cwd=repo / "sub")
    (repo / "sub/s").write_text("dirty\n")
    r = gg.run("git", "checkout", "main", cwd=repo)
    assert r.rc == 0 and "M\tsub" in r.out, r.text
    assert not gg.check(repo).blocked
    r = gg.run("git", "status", cwd=repo)
    assert r.rc == 0 and "sub (new commits, modified content)" in r.out, r.text
    r = gg.run("git", "diff", "--submodule=short", cwd=repo)
    assert "-dirty" in r.out, r.text


def test_stash_pop_in_a_repository_with_a_submodule(gg: GG, repo: Path, subsrc: Path) -> None:
    """[66] ordinary `stash` / `stash pop` with a submodule present: quiet,
    and the status printed by `pop` still lists the restored change."""
    assert gg.git("submodule", "add", "-q", str(subsrc), "sub", cwd=repo).rc == 0
    gg.git("commit", "-qm", "sub", cwd=repo)
    gg.trust(repo)
    (repo / "f").write_text("c\n")
    assert gg.run("git", "stash", "-q", cwd=repo).rc == 0
    r = gg.run("git", "stash", "pop", cwd=repo)
    assert r.rc == 0 and "modified:   f" in r.out, r.text
    assert not gg.check(repo).blocked


def test_every_command_reports_a_dirty_submodule(gg: GG, repo: Path, subsrc: Path) -> None:
    """[66] no switch any more: status, diff, commit's dry run, a shell
    alias (`!git status`, an inner git that inherits the judgment) all
    report a submodule whose own tree is dirty, and `git config --list`
    shows nothing gitguard added."""
    assert gg.git("submodule", "add", "-q", str(subsrc), "sub", cwd=repo).rc == 0
    gg.git("commit", "-qm", "sub", cwd=repo)
    gg.git("config", "--global", "alias.st", "status", cwd=repo)
    gg.git("config", "--global", "alias.s", "st", cwd=repo)
    gg.git("config", "--global", "alias.sst", "!git status", cwd=repo)
    gg.trust(repo)
    (repo / "sub/s").write_text("dirty\n")
    for args in (["status"], ["st"], ["s"]):
        r = gg.run("git", *args, cwd=repo)
        assert r.rc in (0, 1) and "modified content" in r.out, (args, r.text)
    r = gg.run("git", "commit", "--dry-run", cwd=repo)
    assert r.rc in (0, 1) and "modified content" in r.out, r.text
    r = gg.run("git", "status", "--short", cwd=repo)
    assert " m sub" in r.out, r.text
    r = gg.run("git", "diff", "--submodule=log", cwd=repo)
    assert "contains modified content" in r.out, r.text
    r = gg.run("git", "config", "--list", cwd=repo)
    assert "ignoresubmodules" not in r.out.lower(), r.text
    r = gg.run("git", "sst", cwd=repo)
    assert r.rc == 0 and "On branch" in r.out and "modified content" in r.out, r.text
    r = gg.run("git", "log", "-1", "--format=%s", cwd=repo)
    assert r.rc == 0 and r.out.strip() == "sub", r.text
    assert not gg.check(repo).blocked


def test_autocorrected_word_runs(gg: GG, repo: Path) -> None:
    """[78] `git stauts` with help.autocorrect on: git corrects it; gitguard
    has nothing to resolve — no refusal, no prompt."""
    gg.git("config", "--global", "help.autocorrect", "immediate", cwd=repo)
    r = gg.run("git", "stauts", cwd=repo)
    assert r.rc == 0 and "On branch" in r.out, r.text
    assert not gg.check(repo).blocked


def test_branch_edit_description_leaves_its_file(gg: GG, repo: Path) -> None:
    """[83] `git branch --edit-description` leaves .git/EDIT_DESCRIPTION
    behind (its template, rewritten at each edit): volatile. Setting a
    description changes `.git/config`, a trust like any config change; a
    later edit that keeps it is quiet."""
    ed = "sh -c 'echo described > \"$1\"' --"
    assert gg.git("-c", f"core.editor={ed}", "branch", "--edit-description", cwd=repo).rc == 0
    gg.trust(repo)
    (repo / ".git/EDIT_DESCRIPTION").write_text("an older template\n")
    assert gg.git("-c", "core.editor=true", "branch", "--edit-description", cwd=repo).rc == 0
    assert (repo / ".git/EDIT_DESCRIPTION").exists()
    assert not gg.check(repo).blocked, gg.check(repo).text


def test_sparse_checkout_patterns(gg: GG, repo: Path) -> None:
    """[83] `git sparse-checkout set/add` rewrite .git/info/sparse-checkout:
    volatile. Turning sparse checkout on changes `.git/config` (a trust)."""
    for d in ("a", "b", "c"):
        (repo / d).mkdir()
        (repo / d / "f").write_text(d + "\n")
    gg.git("add", "-A", cwd=repo)
    gg.git("commit", "-qm", "dirs", cwd=repo)
    assert gg.git("sparse-checkout", "set", "a", cwd=repo).rc == 0
    gg.trust(repo)
    assert gg.git("sparse-checkout", "set", "b", cwd=repo).rc == 0
    assert gg.git("sparse-checkout", "add", "c", cwd=repo).rc == 0
    assert not gg.check(repo).blocked, gg.check(repo).text
    assert gg.git("sparse-checkout", "reapply", cwd=repo).rc == 0
    assert not gg.check(repo).blocked


def test_editor_aborted_leaves_edit_buffers(gg: GG, repo: Path) -> None:
    """[100] `add -e` and `notes add` with an editor that fails (`:cq`),
    `replace --edit` with one that changes nothing, leave ADD_EDIT.patch,
    NOTES_EDITMSG and REPLACE_EDITOBJ at the gitdir root: data git never
    runs; the next command used to be refused. Found by the inventory of
    git's source (tests/inventory.py), not by a review."""
    gg.env["GIT_EDITOR"] = "false"
    (repo / "f").write_text("b\n")
    gg.git("add", "-e", cwd=repo)
    gg.git("notes", "add", "HEAD", cwd=repo)
    gg.env["GIT_EDITOR"] = "true"
    gg.git("replace", "--edit", "HEAD", cwd=repo)
    left = [n for n in ("ADD_EDIT.patch", "NOTES_EDITMSG", "REPLACE_EDITOBJ")
            if (repo / ".git" / n).exists()]
    assert left, "git left no edit buffer behind: scenario void"
    r = gg.check(repo)
    assert not r.blocked, (left, r.text)
