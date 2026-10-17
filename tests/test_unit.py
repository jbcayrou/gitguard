"""Unit tests of gitguard.py's pure functions (no subprocess)."""
from __future__ import annotations

from pathlib import Path

import pytest

import gitguard as gg_mod
from gitguard import (Entry, Refuse, _unquote, changes, parse_git_config, parse_new_repo,
                      san, split_global_options)


# --------------------------------------------------------------- config parser
def _cfg(tmp_path: Path, text: str) -> list[tuple[str, str, str]]:
    p = tmp_path / "config"
    p.write_text(text)
    return parse_git_config(p)


def test_parse_basic(tmp_path: Path) -> None:
    assert _cfg(tmp_path, "[core]\n\tbare = false\n") == [("core", "bare", "false")]


def test_parse_subsection_and_case(tmp_path: Path) -> None:
    out = _cfg(tmp_path, '[includeIf "gitdir:~/work/"]\n\tPath = ~/.gitconfig-work\n')
    assert out == [("includeif.gitdir:~/work/", "path", "~/.gitconfig-work")]


def test_parse_comments_and_blank(tmp_path: Path) -> None:
    out = _cfg(tmp_path, "# c\n; d\n\n[alias]\n\tst = status # trailing\n")
    assert out == [("alias", "st", "status")]


def test_parse_quotes_keep_hash(tmp_path: Path) -> None:
    out = _cfg(tmp_path, '[alias]\n\tx = "!echo #notacomment"\n')
    assert out == [("alias", "x", "!echo #notacomment")]


def test_parse_escapes_and_continuation(tmp_path: Path) -> None:
    out = _cfg(tmp_path, '[alias]\n\tx = "a\\"b" \\\n\t  c\n')
    assert out == [("alias", "x", 'a"b c')]   # verified: `git config -f` gives exactly this


def test_parse_boolean_without_value(tmp_path: Path) -> None:
    assert _cfg(tmp_path, "[core]\n\tbare\n") == [("core", "bare", "true")]


def test_parse_key_on_section_line(tmp_path: Path) -> None:
    # git accepts a key right after `]` on the same line (verified: `git config -f`)
    out = _cfg(tmp_path, '[core]hooksPath = .githooks\n[core] bare=true\n[x]\n[y "s"]k=v\n')
    assert out == [("core", "hookspath", ".githooks"), ("core", "bare", "true"), ("y.s", "k", "v")]


def test_parse_escaped_backslash_at_eol_is_not_continuation(tmp_path: Path) -> None:
    # `foo\\`: git gives `foo\`; an even number of trailing `\` is not a continuation
    out = _cfg(tmp_path, "[alias]\n\tx = foo\\\\\n\ty = bar\n")
    assert out == [("alias", "x", "foo\\"), ("alias", "y", "bar")]


def test_parse_missing_file(tmp_path: Path) -> None:
    assert parse_git_config(tmp_path / "nope") == []


@pytest.mark.parametrize("raw,expected", [
    ("  x  ", "x"),
    ('"  x  "', "  x  "),
    ("a ; comment", "a"),
    ('"a ; not"', "a ; not"),
    (r"a\tb", "a\tb"),
])
def test_unquote(raw: str, expected: str) -> None:
    assert _unquote(raw) == expected


# ---------------------------------------------------------------- parse_new_repo
@pytest.mark.parametrize("args,expected", [
    (["clone", "https://x/y.git", "d"], ("clone", "d")),
    (["clone", "https://x/y.git"], ("clone", "y")),
    (["clone", "git@h:o/y.git"], ("clone", "y")),
    (["clone", "-q", "--depth", "1", "u", "d"], ("clone", "d")),
    (["-c", "k=v", "clone", "u", "d"], ("clone", "d")),
    (["init", "d"], ("init", "d")),
    (["init"], ("init", ".")),
    (["init", "-q", "--", "d"], ("init", "d")),
])
def test_parse_new_repo_targets(args, expected, monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)
    res = parse_new_repo(args)
    assert res is not None
    assert res[0] == expected[0]
    assert res[1] == (tmp_path / expected[1])


@pytest.mark.parametrize("args", [
    ["status"],
    ["clone", "--bare", "u", "d"],
    ["clone", "--mirror", "u"],
    ["init", "--bare", "d"],
    ["init", "--separate-git-dir=/x", "d"],
    ["clone"],
])
def test_parse_new_repo_none(args, monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)
    assert parse_new_repo(args) is None


def test_parse_new_repo_template_warns(monkeypatch, tmp_path, capsys) -> None:
    monkeypatch.chdir(tmp_path)
    assert parse_new_repo(["clone", "--template=/t", "u", "d"]) is None
    assert "template" in capsys.readouterr().err


def test_parse_new_repo_dash_C(monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "sub").mkdir()
    res = parse_new_repo(["-C", "sub", "init", "d"])
    assert res == ("init", tmp_path / "sub" / "d")


# ------------------------------------------------------- split_global_options
def test_split_global_options_basic() -> None:
    o = split_global_options(["-C", "sub", "--no-pager", "-c", "k=v", "status", "-s"], Path("/w"))
    assert o.cwd == Path("/w/sub") and o.gitdir is None and o.rest == ["status", "-s"]


def test_split_global_options_gitdir_relative_to_dash_C() -> None:
    o = split_global_options(["-C", "a", "--git-dir=g", "log"], Path("/w"))
    assert o.gitdir == Path("/w/a/g")
    o = split_global_options(["--git-dir", "/abs/g", "log"], Path("/w"))
    assert o.gitdir == Path("/abs/g") and o.rest == ["log"]


def test_split_global_options_work_tree_does_not_move() -> None:
    # [18]: --work-tree does not change gitdir discovery; [28]: it is captured
    o = split_global_options(["--work-tree=/elsewhere", "status"], Path("/w"))
    assert o.cwd == Path("/w") and o.rest == ["status"] and o.worktree == Path("/elsewhere")
    o = split_global_options(["-C", "a", "--work-tree", "wt", "status"], Path("/w"))
    assert o.cwd == Path("/w/a") and o.rest == ["status"] and o.worktree == Path("/w/a/wt")


@pytest.mark.parametrize("args", [["-C"], ["--git-dir"], ["-c"], ["-C", "x", "--work-tree"]])
def test_split_global_options_missing_argument(args) -> None:
    with pytest.raises(Refuse):
        split_global_options(args, Path("/w"))


# ----------------------------------------------------------------------- changes
def _e(sha: str, mode: str = "644", kind: str = "f") -> Entry:
    return Entry("local", "x", kind, mode, sha)


def test_changes_classification() -> None:
    old = {("local", "a"): _e("1"), ("local", "b"): _e("2"), ("local", "c"): _e("3")}
    new = {("local", "a"): _e("1"), ("local", "b"): _e("9"), ("local", "d"): _e("4")}
    assert changes(old, new) == [
        ("modified", ("local", "b")),
        ("removed", ("local", "c")),
        ("added", ("local", "d")),
    ]


def test_changes_mode_only() -> None:
    assert changes({("local", "a"): _e("1", "644")}, {("local", "a"): _e("1", "755")}) \
        == [("modified", ("local", "a"))]


def test_changes_symlink_vs_file() -> None:
    assert changes({("local", "a"): _e("1", "644", "f")}, {("local", "a"): _e("1", "l", "l")}) \
        == [("modified", ("local", "a"))]


# ---------------------------------------------------------------------------- san
@pytest.mark.parametrize("raw,expected", [
    ("abc", "abc"),
    ("a\x1b[2Kb", "a?[2Kb"),                       # erase line: neutralized
    ("a\x1b[31mred\x1b[0m", "a\x1b[31mred\x1b[0m"),  # SGR: kept (harmless)
    ("a\x1bb", "a?b"),                             # lone ESC
    ("a\rb\tc", "a?b?c"),                          # carriage return, tab
    ("a\nb", "a\nb"),                              # newline: intended in messages
    ("é✓", "é✓"),                                  # non-ASCII input is preserved as is
    (Path("/x/y"), "/x/y"),
])
def test_san(raw, expected) -> None:
    assert san(raw) == expected


def test_san_keeps_own_colors_in_refuse() -> None:
    """An error message composed with STYLE must keep its colours."""
    st = gg_mod.Style(True)
    msg = "then:  " + st.cyan("gitguard trust")
    assert str(gg_mod.Refuse(msg)) == msg


def test_style_disabled_emits_no_escape() -> None:
    st = gg_mod.Style(False)
    assert "\x1b" not in st.red("x") + st.bold("y")


def test_style_enabled_wraps() -> None:
    st = gg_mod.Style(True)
    assert st.red("x") == "\x1b[31mx\x1b[0m"


def test_refuse_sanitizes_message() -> None:
    assert str(gg_mod.Refuse("a\x1bb")) == "a?b"


# ------------------------------------------------------------ walk_gitdir filter
def test_walk_gitdir_excludes_volatile(tmp_path: Path) -> None:
    g = tmp_path / ".git"
    for d in ["objects/ab", "objects/info", "refs/heads", "logs", "hooks", "rebase-merge"]:
        (g / d).mkdir(parents=True)
    for f in ["HEAD", "index", "config", "description", "objects/ab/cd", "objects/info/packs",
              "objects/info/alternates", "refs/heads/main", "logs/HEAD", "hooks/pre-commit",
              "rebase-merge/x", "BISECT_LOG", "foo.lock", "myhooks"]:
        (g / f).write_text("x")
    paths = sorted(e.path for e in gg_mod.walk_gitdir(g, "local"))
    assert paths == ["config", "description", "hooks/pre-commit", "myhooks",
                     "objects/info/alternates"]


def test_walk_gitdir_anchors_roots_under_modules_only(tmp_path: Path) -> None:
    """[26] a submodule's info/refs (modules/lib/foo/) is volatile; [29] a forged
    HEAD under hooks/ does not make hooks/ a root."""
    g = tmp_path / ".git"
    for d in ["modules/lib/foo/info", "modules/lib/foo/refs", "modules/lib/foo/objects/pack",
              "hooks/refs", "worktrees/wt/logs"]:
        (g / d).mkdir(parents=True)
    for f in ["HEAD", "config", "modules/lib/foo/HEAD", "modules/lib/foo/config",
              "modules/lib/foo/info/refs", "modules/lib/foo/refs/x", "modules/lib/foo/objects/pack/p",
              "modules/lib/foo/objects/info/packs", "hooks/HEAD", "hooks/refs/x", "hooks/index",
              "worktrees/wt/HEAD", "worktrees/wt/commondir", "worktrees/wt/logs/HEAD"]:
        (g / f).parent.mkdir(parents=True, exist_ok=True)
        (g / f).write_text("x")
    paths = sorted(e.path for e in gg_mod.walk_gitdir(g, "local"))
    assert paths == ["config", "hooks/HEAD", "hooks/index", "hooks/refs/x",
                     "modules/lib/foo/config", "worktrees/wt/commondir"]
    assert gg_mod.gitdir_excluded(g / "modules/lib/foo/info/refs", g)
    assert gg_mod.gitdir_excluded(g / "modules/lib/foo/refs/x", g)
    assert not gg_mod.gitdir_excluded(g / "hooks/refs/x", g)
    assert not gg_mod.gitdir_excluded(g / "modules/lib/foo/config", g)


def test_walk_error_ignores_vanished_dir_but_refuses_permission() -> None:
    gg_mod._walk_error(FileNotFoundError(2, "No such file or directory", "/x"))
    with pytest.raises(gg_mod.Refuse):
        gg_mod._walk_error(PermissionError(13, "Permission denied", "/x"))


# --------------------------------------------------------------- index_gitlinks
def _index_v2(entries: list[tuple[int, bytes]]) -> bytes:
    """Minimal DIRC v2 index: (mode, name) per entry, no extension."""
    import hashlib
    body = b"DIRC" + (2).to_bytes(4, "big") + len(entries).to_bytes(4, "big")
    for mode, name in entries:
        e = b"\0" * 24 + mode.to_bytes(4, "big") + b"\0" * 12 + b"\0" * 20
        e += len(name).to_bytes(2, "big") + name
        e += b"\0" * (((len(e) + 8) & ~7) - len(e))
        body += e
    return body + hashlib.sha1(body).digest()


@pytest.mark.parametrize("entries, expected", [
    ([(0o100644, b"f"), (0o100755, b"dir/x.sh")], []),
    ([(0o100644, b"f"), (0o160000, b"vendor")], ["vendor"]),
    # git recognises a gitlink by (mode & 0xF000) == 0xE000: a forged mode with
    # permission bits must be seen too (a byte-pattern shortcut on
    # `00 00 Ex` must not miss it).
    ([(0o160777, b"forged")], ["forged"]),
    ([(0o120000, b"link"), (0o160000, b"a/b"), (0o100644, b"z")], ["a/b"]),
    ([], []),
])
def test_index_gitlinks_minimal_index(tmp_path: Path, entries, expected) -> None:
    (tmp_path / "index").write_bytes(_index_v2(entries))
    assert gg_mod.index_gitlinks(tmp_path) == expected


def test_index_gitlinks_cache(tmp_path: Path) -> None:
    """The cache is reused while the index sha256 is identical, ignored
    otherwise (modified index or forged/corrupt cache), and never written on
    refusal."""
    import json
    idx = tmp_path / "index"
    cache = tmp_path / "state" / "k.idx"
    cache.parent.mkdir()
    idx.write_bytes(_index_v2([(0o100644, b"f"), (0o160000, b"vendor")]))
    assert gg_mod.index_gitlinks(tmp_path, cache) == ["vendor"]
    c = json.loads(cache.read_text())
    assert c["gitlinks"] == ["vendor"] and len(c["sha256"]) == 64
    # Consistent cache: reused as is (we tamper with it to prove it).
    cache.write_text(json.dumps({"sha256": c["sha256"], "gitlinks": ["from-cache"]}))
    assert gg_mod.index_gitlinks(tmp_path, cache) == ["from-cache"]
    # Modified index: the cache no longer matches, re-parsed and rewritten.
    idx.write_bytes(_index_v2([(0o100644, b"f"), (0o160000, b"other")]))
    assert gg_mod.index_gitlinks(tmp_path, cache) == ["other"]
    assert json.loads(cache.read_text())["gitlinks"] == ["other"]
    # Corrupt or malformed cache: ignored.
    for bad in ("{", "[]", json.dumps({"sha256": "x", "gitlinks": ["a"]}),
                json.dumps({"sha256": json.loads(cache.read_text())["sha256"], "gitlinks": "a"})):
        cache.write_text(bad)
        assert gg_mod.index_gitlinks(tmp_path, cache) == ["other"]
    # Parser refusal: nothing is written.
    cache.unlink()
    forged = bytearray(_index_v2([(0o160000, b"vendor")]))
    forged[72:74] = (3).to_bytes(2, "big")          # namelen 3 != real NUL at 6
    idx.write_bytes(bytes(forged))
    with pytest.raises(Refuse):
        gg_mod.index_gitlinks(tmp_path, cache)
    assert not cache.exists()
    # Missing state directory: no error, correct result.
    idx.write_bytes(_index_v2([(0o160000, b"v")]))
    assert gg_mod.index_gitlinks(tmp_path, tmp_path / "nope" / "k.idx") == ["v"]


# ------------------------------------------------------- branch_tracking_only
BASE = [("core", "bare", "false"), ("remote.origin", "url", "/x"),
        ("remote.origin", "fetch", "+refs/heads/*:refs/remotes/origin/*")]
TRACK = [("branch.feat", "remote", "origin"), ("branch.feat", "merge", "refs/heads/feat")]


@pytest.mark.parametrize("old, new, expected", [
    (BASE, BASE + TRACK, ["feat"]),                                  # push -u
    (BASE + TRACK, BASE, ["feat"]),                                  # branch -d / --unset-upstream
    (BASE, BASE + TRACK + [("branch.main", "remote", "."), ("branch.main", "merge", "refs/heads/dev")],
     ["feat", "main"]),
    (BASE, BASE, []),                                                # nothing
    (BASE, BASE + [("branch.feat", "remote", "evil")], []),          # unknown remote
    (BASE, BASE + [("branch.feat", "merge", "../../x")], []),        # not refs/heads/
    (BASE, BASE + [("branch.feat", "merge", "refs/heads/a b")], []),
    (BASE, BASE + [("branch.feat", "rebase", "true")], []),          # key outside the list
    (BASE, BASE + TRACK + [("core", "fsmonitor", "/tmp/evil")], []), # something else as well
    (BASE, BASE + TRACK + [("remote.evil", "url", "ext::sh")], []),
    (BASE, [("core", "bare", "false")] + TRACK, []),                 # a remote disappeared
    (BASE, BASE + [("branch.", "remote", "origin")], []),            # empty name
    (BASE, BASE + [("branch.a\x1b[2Jb", "remote", "origin")], []),   # control char in the name
    (BASE + TRACK, BASE + [("branch.feat", "remote", "origin"), ("branch.feat", "merge", "refs/heads/other")],
     ["feat"]),                                                      # merge changed
])
def test_branch_tracking_only(old, new, expected) -> None:
    assert gg_mod.branch_tracking_only(old, new) == expected
