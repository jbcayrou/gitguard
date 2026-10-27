"""Unit tests of gitguard.py's pure functions (no subprocess)."""
from __future__ import annotations

from pathlib import Path

import os
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
    # git 2.50 keeps the internal whitespace as is (verified with `git config -f`)
    assert out == [("alias", "x", 'a"b \t  c')]


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
    assert (res.sub, res.dir, res.gitdir, res.auto_trust) == (expected[0], tmp_path / expected[1], None, True)


@pytest.mark.parametrize("args", [["status"], ["clone"], ["clone", "/"]])
def test_parse_new_repo_none(args, monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)
    assert parse_new_repo(args) is None


@pytest.mark.parametrize("args,dir,gitdir", [
    (["clone", "--bare", "u", "d"], "d", None),
    (["clone", "--mirror", "u"], "u.git", None),
    (["init", "--bare", "d"], "d", None),
    (["init", "--bare"], ".", None),
])
def test_parse_new_repo_bare_sets_the_marker_without_auto_trust(args, dir, gitdir, monkeypatch, tmp_path) -> None:
    """A bare repository is not auto-trusted (gitguard does not handle
    those), but its clone's index-pack still needs the `new` marker. [101]"""
    monkeypatch.chdir(tmp_path)
    res = parse_new_repo(args)
    assert (res.dir, res.gitdir, res.auto_trust) == (tmp_path / dir, None, False)


@pytest.mark.parametrize("args", [["init", "--separate-git-dir=g", "d"], ["init", "--separate-git-dir", "g", "d"],
                                  ["clone", "--separate-git-dir=g", "u", "d"], ["clone", "--sep=g", "u", "d"]])
def test_parse_new_repo_separate_git_dir(args, monkeypatch, tmp_path) -> None:
    """`--separate-git-dir`: the gitdir is elsewhere; the marker names it
    too (the clone's index-pack runs with GIT_DIR there). [101]"""
    monkeypatch.chdir(tmp_path)
    res = parse_new_repo(args)
    assert (res.dir, res.gitdir, res.auto_trust) == (tmp_path / "d", tmp_path / "g", True)
    assert res.paths == [str((tmp_path / "d").resolve()), str((tmp_path / "g").resolve())]


def test_parse_new_repo_template_warns(monkeypatch, tmp_path, capsys) -> None:
    monkeypatch.chdir(tmp_path)
    res = parse_new_repo(["clone", "--template=/t", "u", "d"])
    assert res.dir == tmp_path / "d" and not res.auto_trust
    assert "template" in capsys.readouterr().err


def test_parse_new_repo_dash_C(monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "sub").mkdir()
    res = parse_new_repo(["-C", "sub", "init", "d"])
    assert (res.sub, res.dir) == ("init", tmp_path / "sub" / "d")


@pytest.mark.parametrize("url,bundle,bare,expected", [
    ("x/.git", False, False, "x"),                 # [110]: was "" (the `.git` cut, nothing after the `/`)
    ("x/.git/", False, False, "x"),
    ("/p/x.git", False, False, "x"),
    ("/p/x.git/", False, False, "x"),
    ("https://h/o/x.git", False, False, "x"),
    ("ssh://user@h:22/o/x", False, False, "x"),
    ("user@h:x.git", False, False, "x"),
    ("h:x", False, False, "x"),
    ("h:2222", False, False, "h"),                 # a bare host:port: the port is stripped
    ("/foo/bar:2222.git", False, False, "2222"),   # git's documented oddity
    ("/p/x.bundle", True, False, "x"),
    ("/p/x.bundle", False, False, "x.bundle"),
    ("/p/x", False, True, "x.git"),
    ("/p/x.git", False, True, "x.git"),
    ("/p/a  b\tc ", False, False, "a b c"),
    ("/", False, False, None),
    ("", False, False, None),
])
def test_guess_dir_name_is_git_url_basename(url, bundle, bare, expected) -> None:
    assert gg_mod._guess_dir_name(url, bundle, bare) == expected


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


# ------------------------------------------------------------ the judged marker
def _hex(p: str) -> str:
    return os.fsencode(p).hex()


def test_judged_marker_round_trip(monkeypatch) -> None:
    monkeypatch.delenv("GITGUARD_JUDGED", raising=False)
    assert gg_mod.read_judged() is None
    gg_mod.set_judged("repo", "/g/.git", "/g/.git", "/g")
    j = gg_mod.read_judged()
    assert j.kind == "repo" and j.paths == ["/g/.git", "/g/.git", "/g"] and j.pid == os.getpid() and j.alive
    gg_mod.set_judged("repo", "/srv/x.git", "/srv/x.git", "")          # served: no tree
    assert gg_mod.read_judged().paths == ["/srv/x.git", "/srv/x.git", ""]
    gg_mod.set_judged("new", "/p=a:th,\N{EURO SIGN}", "/else/where")   # anything but NUL
    j = gg_mod.read_judged()
    assert j.kind == "new" and j.paths == ["/p=a:th,\N{EURO SIGN}", "/else/where"]


@pytest.mark.parametrize("bad", ["", "x", "123", "123:other=1", "123:repo", "123:repo=", "abc:repo=2f",
                                 f"123:repo={_hex('/a')}", f"123:repo=,{_hex('/a')},{_hex('/a')}",
                                 f"123:new=", f"123:new={_hex('/a')},{_hex('/b')},{_hex('/c')}",
                                 "123:repo=zz,zz,zz", "123:serving"])
def test_judged_marker_malformed_is_refused(monkeypatch, bad: str) -> None:
    monkeypatch.setenv("GITGUARD_JUDGED", bad)
    with pytest.raises(gg_mod.Refuse):
        gg_mod.read_judged()


def test_judged_marker_dies_with_its_process(monkeypatch) -> None:
    """[104] the marker is valid while the process that set it is an
    ancestor: a dead pid, or a live one outside the chain, is no marker —
    and no TTL: a clock changed the answer mid-command."""
    import subprocess
    anc = gg_mod._ancestors()
    assert os.getpid() in anc and os.getppid() in anc
    body = f"123:repo={_hex('/a')},{_hex('/a')},{_hex('/a')}"
    monkeypatch.setenv("GITGUARD_JUDGED", f"{os.getpid()}:" + body.partition(":")[2])
    assert gg_mod.read_judged() is not None
    dead = subprocess.Popen(["true"]); dead.wait()
    monkeypatch.setenv("GITGUARD_JUDGED", f"{dead.pid}:" + body.partition(":")[2])
    assert gg_mod.read_judged() is None
    alive = subprocess.Popen(["sleep", "5"])
    try:
        monkeypatch.setenv("GITGUARD_JUDGED", f"{alive.pid}:" + body.partition(":")[2])
        assert gg_mod.read_judged() is None, "alive but not an ancestor"
    finally:
        alive.kill(); alive.wait()
    assert not hasattr(gg_mod, "judged_ttl") and "GITGUARD_JUDGED_TTL" not in open(gg_mod.__file__).read()


def _layout(tmp_path: Path) -> tuple[Path, Path]:
    """A main repository with a submodule `sub` (which has its own
    submodule `inner`), a linked worktree `wt` with a submodule `a`, and a
    gitdir planted in `sub`'s volatile `refs/`: only the directories the
    recognition needs (HEAD / commondir)."""
    root = tmp_path / "r"
    g = root / ".git"
    for d in ["modules/sub", "modules/sub/modules/inner", "worktrees/wt", "worktrees/wt/modules/a",
              "modules/sub/refs/p", "hooks/x"]:
        (g / d).mkdir(parents=True)
    for d in ["", "modules/sub", "modules/sub/modules/inner", "worktrees/wt/modules/a", "modules/sub/refs/p"]:
        (g / d / "HEAD").write_text("ref: refs/heads/main\n")
    (g / "worktrees/wt/commondir").write_text("../..\n")
    return root, g


def _repo(root: Path, gitdir: Path, common: Path | None = None) -> "gg_mod.Repo":
    return gg_mod.Repo(root, gitdir, common or gitdir, root)


def test_judged_covers_what_the_walk_hashed(tmp_path: Path, monkeypatch) -> None:
    """[102] [103] coverage = the judged gitdir and common dir and the gitdir
    roots nested under their modules/ and worktrees/ (gitdir_roots): a
    submodule, a submodule's submodule, a worktree's submodule, whatever
    the gitdir's name; never a gitdir planted in a volatile zone, nor
    `hooks/x`, nor another repository; the same gitdir with another tree
    is judged."""
    root, g = _layout(tmp_path)
    gg_mod.set_judged("repo", str(g), str(g), str(root))
    j = gg_mod.read_judged()
    assert j.covers(_repo(root, g))
    assert j.covers(_repo(root / "sub", g / "modules/sub"))
    assert j.covers(_repo(root / "sub/inner", g / "modules/sub/modules/inner"))
    assert j.covers(_repo(tmp_path / "wt", g / "worktrees/wt", g))
    assert j.covers(_repo(tmp_path / "wt/a", g / "worktrees/wt/modules/a"))
    assert not j.covers(_repo(root / "vendor/x", g / "modules/sub/refs/p")), "[103] volatile zone"
    assert not j.covers(_repo(root / "h", g / "hooks/x"))
    assert not j.covers(_repo(tmp_path / "other", tmp_path / "other/.git"))
    assert not j.covers(_repo(tmp_path / "elsewhere", g)), "same gitdir, another tree [72]"
    assert not j.covers(_repo(tmp_path / "wt", g / "worktrees/wt", tmp_path / "planted")), "planted commondir"
    # judged from the worktree (its own key): its submodule is covered, the main's too (common)
    gg_mod.set_judged("repo", str(g / "worktrees/wt"), str(g), str(tmp_path / "wt"))
    j = gg_mod.read_judged()
    assert j.covers(_repo(tmp_path / "wt/a", g / "worktrees/wt/modules/a"))
    assert j.covers(_repo(root / "sub", g / "modules/sub"))
    assert not j.covers(_repo(root / "vendor/x", g / "modules/sub/refs/p"))
    # judged from inside the submodule: its own submodule is covered, the superproject is not
    gg_mod.set_judged("repo", str(g / "modules/sub"), str(g / "modules/sub"), str(root / "sub"))
    j = gg_mod.read_judged()
    assert j.covers(_repo(root / "sub/inner", g / "modules/sub/modules/inner"))
    assert not j.covers(_repo(root, g))
    # served: any tree of the same gitdir, nothing else
    gg_mod.set_judged("repo", str(g), str(g), "")
    j = gg_mod.read_judged()
    assert j.covers(_repo(tmp_path / "whatever", g)) and j.covers(_repo(root / "sub", g / "modules/sub"))
    assert not j.covers(_repo(tmp_path / "other", tmp_path / "other/.git"))
    # a clone in progress: gitdir, common or root under the new path
    gg_mod.set_judged("new", str(tmp_path / "new"), str(tmp_path / "sep"))
    j = gg_mod.read_judged()
    assert j.covers(_repo(tmp_path, tmp_path / "new/.git")), "[101] index-pack: GIT_DIR under new, cwd elsewhere"
    assert j.covers(_repo(tmp_path / "new/sub", tmp_path / "new/.git/modules/sub"))
    assert j.covers(_repo(tmp_path / "new", tmp_path / "sep")), "--separate-git-dir"
    assert not j.covers(_repo(tmp_path / "newer", tmp_path / "newer/.git"))


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
def _index_v2(entries: list[tuple[int, bytes]], ext: bytes = b"") -> bytes:
    """Minimal DIRC v2 index: (mode, name) per entry, then `ext` (raw
    extensions: signature, size, data)."""
    import hashlib
    body = b"DIRC" + (2).to_bytes(4, "big") + len(entries).to_bytes(4, "big")
    for mode, name in entries:
        e = b"\0" * 24 + mode.to_bytes(4, "big") + b"\0" * 12 + b"\0" * 20
        e += len(name).to_bytes(2, "big") + name
        e += b"\0" * (((len(e) + 8) & ~7) - len(e))
        body += e
    body += ext
    return body + hashlib.sha1(body).digest()


def _ext(sig: bytes, data: bytes = b"") -> bytes:
    return sig + len(data).to_bytes(4, "big") + data


def test_index_sparse_directories_and_extensions(tmp_path: Path) -> None:
    """[87] a sparse directory (mode 040000, `sdir`) is returned for the
    caller to look on disk; an optional extension (uppercase signature) is
    skipped, a required one gitguard does not know is refused as git dies
    on it, `link` (split index) too."""
    idx = tmp_path / "index"
    idx.write_bytes(_index_v2([(0o100644, b"src/a"), (0o040000, b"vendor/")],
                              _ext(b"TREE", b"xx") + _ext(b"sdir")))
    assert gg_mod.index_entries(idx) == ([], ["vendor/"])
    idx.write_bytes(_index_v2([(0o160000, b"v")], _ext(b"UNTR", b"abc") + _ext(b"EOIE", b"x" * 24)))
    assert gg_mod.index_entries(idx) == (["v"], [])
    idx.write_bytes(_index_v2([(0o160000, b"v")], _ext(b"zzzz")))
    with pytest.raises(Refuse, match="does not know"):
        gg_mod.index_entries(idx)
    idx.write_bytes(_index_v2([(0o160000, b"v")], _ext(b"link", b"\0" * 20)))
    with pytest.raises(Refuse, match="splitIndex"):
        gg_mod.index_entries(idx)


def test_index_nested_walks_a_sparse_directory_on_disk(tmp_path: Path) -> None:
    """[87] a nested `.git` at any depth of a sparse directory present on
    disk; nothing for an absent one, nor below a `.git`."""
    (tmp_path / "vendor/a/evil/.git/x/.git").mkdir(parents=True)
    (tmp_path / "vendor/b").mkdir()
    (tmp_path / "vendor/b/.git").write_text("gitdir: ../../.git/modules/b\n")
    got = gg_mod.index_nested(tmp_path, [], ["vendor/", "absent/"])
    assert got == {tmp_path / "vendor/a/evil/.git", tmp_path / "vendor/b/.git"}


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
    assert gg_mod.index_gitlinks(tmp_path / "index") == expected


def test_index_gitlinks_cache(tmp_path: Path) -> None:
    """The cache is reused while the index sha256 is identical, ignored
    otherwise (modified index, forged/corrupt cache, older cache version that
    never checked names [55]), and never written on refusal."""
    import json
    idx = tmp_path / "index"
    cache = tmp_path / "state" / "k.idx"
    cache.parent.mkdir()
    idx.write_bytes(_index_v2([(0o100644, b"f"), (0o160000, b"vendor")]))
    assert gg_mod.index_gitlinks(idx, cache) == ["vendor"]
    c = json.loads(cache.read_text())
    rec = c["indexes"][str(idx)]
    assert c["v"] == gg_mod.INDEX_CACHE_VERSION
    assert rec["gitlinks"] == ["vendor"] and len(rec["sha256"]) == 64
    def put(gitlinks, sha=rec["sha256"], v=gg_mod.INDEX_CACHE_VERSION):
        cache.write_text(json.dumps({"v": v, "indexes": {str(idx): {"sha256": sha,
                                                                    "gitlinks": gitlinks,
                                                                    "sparse": []}}}))
    # Consistent cache: reused as is (we tamper with it to prove it).
    put(["from-cache"])
    assert gg_mod.index_gitlinks(idx, cache) == ["from-cache"]
    # Version 1 (flat, no name check) is ignored, even with the right sha256.
    cache.write_text(json.dumps({"sha256": rec["sha256"], "gitlinks": ["v1"]}))
    assert gg_mod.index_gitlinks(idx, cache) == ["vendor"]
    put(["old"], v=1)
    assert gg_mod.index_gitlinks(idx, cache) == ["vendor"]
    put(["old"], v=2)                           # before [87]: no sparse directories
    assert gg_mod.index_gitlinks(idx, cache) == ["vendor"]
    # Modified index: the cache no longer matches, re-parsed and rewritten.
    idx.write_bytes(_index_v2([(0o100644, b"f"), (0o160000, b"other")]))
    assert gg_mod.index_gitlinks(idx, cache) == ["other"]
    rec = json.loads(cache.read_text())["indexes"][str(idx)]
    assert rec["gitlinks"] == ["other"]
    # A second index file gets its own record, the first one is kept.
    idx2 = tmp_path / "sub" / "index"
    idx2.parent.mkdir()
    idx2.write_bytes(_index_v2([(0o160000, b"nested")]))
    assert gg_mod.index_gitlinks(idx2, cache) == ["nested"]
    assert set(json.loads(cache.read_text())["indexes"]) == {str(idx), str(idx2)}
    # Corrupt or malformed cache: ignored.
    for bad in ("{", "[]", json.dumps({"v": 2, "indexes": []}),
                json.dumps({"v": 2, "indexes": {str(idx): {"sha256": "x", "gitlinks": ["a"]}}}),
                json.dumps({"v": 2, "indexes": {str(idx): {"sha256": rec["sha256"],
                                                           "gitlinks": "a"}}})):
        cache.write_text(bad)
        assert gg_mod.index_gitlinks(idx, cache) == ["other"]
    # Parser refusal: nothing is written.
    cache.unlink()
    forged = bytearray(_index_v2([(0o160000, b"vendor")]))
    forged[72:74] = (3).to_bytes(2, "big")          # namelen 3 != real NUL at 6
    idx.write_bytes(bytes(forged))
    with pytest.raises(Refuse):
        gg_mod.index_gitlinks(idx, cache)
    assert not cache.exists()
    # Forged name: refused, nothing cached. [55]
    idx.write_bytes(_index_v2([(0o100644, b".git/hooks/post-checkout")]))
    with pytest.raises(Refuse, match="forged git index"):
        gg_mod.index_gitlinks(idx, cache)
    assert not cache.exists()
    # Missing state directory: no error, correct result.
    idx.write_bytes(_index_v2([(0o160000, b"v")]))
    assert gg_mod.index_gitlinks(tmp_path / "index", tmp_path / "nope" / "k.idx") == ["v"]


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
    (BASE + TRACK, BASE + TRACK + [("branch.feat", "vscode-merge-base", "origin/main")], ["feat"]),  # VS Code on open
    (BASE + TRACK + [("branch.feat", "vscode-merge-base", "origin/main")], BASE + TRACK, ["feat"]),
    (BASE, BASE + [("branch.feat", "vscode-merge-base", "--upload-pack=evil")], []),   # an option, not a ref
    (BASE, BASE + [("branch.feat", "vscode-merge-base", "a b")], []),
    (BASE, BASE + [("branch.feat", "vscode-merge-base", "")], []),
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


# ------------------------------------------- pass 8: global options, display
def test_split_global_options_gitdir_resolved_after_all_dash_C() -> None:
    """[41] git applies -C at once but resolves a relative --git-dir /
    --work-tree from the final cwd: `--git-dir=.git -C repo` is repo/.git."""
    o = split_global_options(["--git-dir=.git", "-C", "repo", "status"], Path("/w"))
    assert o.cwd == Path("/w/repo") and o.gitdir == Path("/w/repo/.git")
    o = split_global_options(["--work-tree", "t", "-C", "a", "--git-dir", "g", "log"], Path("/w"))
    assert o.gitdir == Path("/w/a/g") and o.worktree == Path("/w/a/t")


@pytest.mark.parametrize("opt", ["--config-env", "--attr-source", "--shallow-file"])
def test_split_global_options_separate_argument(opt) -> None:
    """[40] options taking a separate argument: the argument is not the
    subcommand, and the -C that follows is honoured"""
    o = split_global_options([opt, "x=Y", "-C", "repo", "status"], Path("/w"))
    assert o.cwd == Path("/w/repo") and o.rest == ["status"]


def test_split_global_options_unknown_option_refused() -> None:
    """[40] an option gitguard does not know may take an argument: refuse
    rather than guess (git refuses unknown options too)"""
    with pytest.raises(Refuse):
        split_global_options(["--frobnicate", "x", "-C", "repo", "status"], Path("/w"))


@pytest.mark.parametrize("raw", [
    "a\x1b[8mhidden\x1b[0m",          # conceal
    "a\x1b[30;40mhidden\x1b[0m",      # black on black
    "a\x1b[38;5;0;48;5;0mhidden",     # 256-colour fg = bg
    "a\x1b[2;8mhidden",
])
def test_san_neutralizes_hiding_sgr(raw) -> None:
    """[43] an SGR sequence from a file (config diff shown before [y/N]) could
    hide the rest of the line; only gitguard's own codes are kept"""
    assert "\x1b" not in san(raw).replace("\x1b[0m", "")


# ---------------------------------------------------------------- real_git
def test_real_git_skips_itself(tmp_path: Path, monkeypatch) -> None:
    import os
    me = tmp_path / "me"
    me.mkdir()
    os.symlink(Path(gg_mod.__file__).resolve(), me / "git")
    other = tmp_path / "other"
    other.mkdir()
    (other / "git").write_text("#!/bin/sh\n")
    (other / "git").chmod(0o755)
    (tmp_path / "notexec").mkdir()
    (tmp_path / "notexec/git").write_text("")
    monkeypatch.delenv("GITGUARD_REAL_GIT", raising=False)
    monkeypatch.setenv("PATH", os.pathsep.join([str(me), str(tmp_path / "notexec"), str(other)]))
    assert gg_mod.real_git() == str(other / "git")
    monkeypatch.setenv("PATH", str(me))
    with pytest.raises(Refuse):
        gg_mod.real_git()
    monkeypatch.setenv("GITGUARD_REAL_GIT", "/x/git")
    assert gg_mod.real_git() == "/x/git"


# ------------------------------------------------------------------ pending
def test_notify_pending_calls_once_with_sanitized_text(monkeypatch, tmp_path: Path) -> None:
    import subprocess
    import sys
    calls = []
    monkeypatch.setattr(subprocess, "run", lambda cmd, **kw: calls.append(cmd))
    monkeypatch.setattr(gg_mod, "NOTIFY_SEND", sys.executable)        # "exists": that branch is taken
    monkeypatch.delenv("GITGUARD_NO_NOTIFY", raising=False)
    gg_mod.notify_pending(Path("/r/\x1b[2Kevil"), "x" * 500)
    assert len(calls) == 1 and calls[0][0] == sys.executable
    body = calls[0][-1]
    assert "\x1b" not in body and len(body) <= 200
    monkeypatch.setenv("GITGUARD_NO_NOTIFY", "1")
    gg_mod.notify_pending(Path("/r"), "y")
    assert len(calls) == 1


def test_notify_pending_swallows_failures(monkeypatch) -> None:
    import subprocess
    import sys

    def boom(*a, **k):
        raise OSError("no bus")
    monkeypatch.setattr(subprocess, "run", boom)
    monkeypatch.setattr(gg_mod, "NOTIFY_SEND", sys.executable)
    monkeypatch.delenv("GITGUARD_NO_NOTIFY", raising=False)
    gg_mod.notify_pending(Path("/r"), "y")          # no exception


def test_record_pending_notifies_once_per_cooldown(monkeypatch, tmp_path: Path) -> None:
    sent = []
    monkeypatch.setattr(gg_mod, "STATE", tmp_path / "state")
    monkeypatch.setattr(gg_mod, "notify_pending", lambda label, text: sent.append(text))
    key = gg_mod.key_for(Path("/some/repo"))
    gg_mod.record_pending(key, "never", Path("/some/repo"), "never trusted")
    gg_mod.record_pending(key, "never", Path("/some/repo"), "never trusted")
    assert len(sent) == 1
    d = gg_mod.load_pending(key)
    d["notified"] -= gg_mod.NOTIFY_COOLDOWN + 1
    gg_mod.update_pending(key, lambda cur: d)
    gg_mod.record_pending(key, "never", Path("/some/repo"), "never trusted")
    assert len(sent) == 2
    assert (tmp_path / "state").stat().st_mode & 0o777 == 0o700


def test_update_pending_is_atomic_under_concurrency(monkeypatch, tmp_path: Path) -> None:
    from concurrent.futures import ThreadPoolExecutor
    monkeypatch.setattr(gg_mod, "STATE", tmp_path / "state")
    key = gg_mod.key_for(Path("/some/repo"))
    gg_mod.update_pending(key, lambda cur: {"root": "/some/repo", "kind": "changed", "waiters": []})

    def add(i: int) -> None:
        def fn(cur):
            cur["waiters"].append({"pid": i})
            return cur
        gg_mod.update_pending(key, fn)
    with ThreadPoolExecutor(8) as ex:
        list(ex.map(add, range(200)))
    assert len(gg_mod.load_pending(key)["waiters"]) == 200


def test_caller_chain_starts_with_our_parent() -> None:
    import os
    chain = gg_mod.caller_chain()
    assert chain and chain[0]["pid"] == os.getppid()
    assert all(set(c) == {"pid", "name", "args"} for c in chain)


def test_wait_seconds(monkeypatch) -> None:
    monkeypatch.delenv("GITGUARD_WAIT", raising=False)
    assert gg_mod.wait_seconds() == gg_mod.WAIT_DEFAULT
    monkeypatch.setenv("GITGUARD_WAIT", "2.5")
    assert gg_mod.wait_seconds() == 2.5
    monkeypatch.setenv("GITGUARD_WAIT", "-1")
    with pytest.raises(Refuse):
        gg_mod.wait_seconds()
    monkeypatch.setenv("GITGUARD_WAIT", "soon")
    with pytest.raises(Refuse):
        gg_mod.wait_seconds()


# ------------------------------------------------------------- state directory
def test_state_dir_order(monkeypatch, tmp_path: Path) -> None:
    """GITGUARD_STATE, else an absolute XDG_STATE_HOME, else ~/.local/state;
    a relative XDG_STATE_HOME is invalid per the spec and ignored."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("GITGUARD_STATE", raising=False)
    monkeypatch.delenv("XDG_STATE_HOME", raising=False)
    assert gg_mod.state_dir() == tmp_path / ".local/state/gitguard"
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "xdg"))
    assert gg_mod.state_dir() == tmp_path / "xdg/gitguard"
    monkeypatch.setenv("XDG_STATE_HOME", "relative/state")
    assert gg_mod.state_dir() == tmp_path / ".local/state/gitguard"
    monkeypatch.setenv("XDG_STATE_HOME", "")
    assert gg_mod.state_dir() == tmp_path / ".local/state/gitguard"
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "xdg"))
    monkeypatch.setenv("GITGUARD_STATE", str(tmp_path / "explicit"))
    assert gg_mod.state_dir() == tmp_path / "explicit"


# ------------------------------------------------------------ aliases [66]
@pytest.mark.parametrize("value, word", [
    ("checkout", "checkout"),
    ("checkout main", "checkout"),
    ("  checkout", None),               # a leading blank: git's first word is empty
    ("'switch' --no-guess", "switch"),
    ('"check"out', "checkout"),
    ("check\\out", "checkout"),
    ("'check\\out'", "check\\out"),     # no escape inside single quotes
    ("'' checkout", None),
    ("!git checkout", None),
    ("", None),
    ("'checkout", None),                # unclosed quote: git dies
    ("checkout \\", None),              # trailing backslash: git dies
    ("checkout 'a", None),
    ("checkout\vmain", "checkout\vmain"),   # git's isspace: \v and \f are not blanks
])
def test_alias_command(value: str, word: str | None) -> None:
    """The command word of _alias_parts: the oracle of its split and of the
    options it skips, so that the `-c` pairs land where git reads them. [80]"""
    assert gg_mod._alias_parts(value)[0] == word


@pytest.mark.parametrize("value, words", [
    ("a b", ["a", "b"]), (" a", ["", "a"]), ("a ", ["a", ""]), ("", [""]),
    ("a  \t b", ["a", "b"]), ("'a b' c", ["a b", "c"]), ('"a\\"b" c', ['a"b', "c"]),
    ("a\\ b", ["a b"]), ("'a\\b'", ["a\\b"]), ("a\vb", ["a\vb"]),
    ("'a", None), ("a\\", None),
])
def test_split_cmdline(value: str, words: list | None) -> None:
    assert gg_mod._split_cmdline(value) == words


@pytest.mark.parametrize("value, command, pairs", [
    ("checkout -q", "checkout", []),
    ("-p checkout", "checkout", []),
    ("--paginate -p checkout", "checkout", []),
    ("-c color.ui=auto checkout", "checkout", [("color.ui", "auto")]),
    ("-c core.hooksPath=.githooks -c x.y commit", "commit", [("core.hooksPath", ".githooks"), ("x.y", None)]),
    ("--config-env=core.pager=HOME log", "log", [("core.pager", "/home/user")]),
    ("--config-env core.pager=NO_SUCH_VAR_X log", "log", []),
    ("-C sub checkout", "checkout", []),                      # git dies; a superset
    ("--no-pager checkout", "checkout", []),
    ("-c", None, []), ("-p", None, []), ("--help", None, []),
    ("!git checkout", None, []), ("'checkout", None, []),
])
def test_alias_parts(monkeypatch, value: str, command: str | None, pairs: list) -> None:
    monkeypatch.setenv("HOME", "/home/user")
    monkeypatch.delenv("NO_SUCH_VAR_X", raising=False)
    assert gg_mod._alias_parts(value) == (command, pairs)


@pytest.mark.parametrize("tok, want", [
    ("-F./c", {"./c"}),
    ("-vF./c", {"F./c", "./c"}),
    ("-i~/.ssh/k", {"~/.ssh/k"}),
    ("-ikey", {"key", "ey", "y", ""}),
    ("--file=./c", set()),               # split on `=` by _value_tokens
    ("./c", set()),
    ("-", set()),
])
def test_glued_values(tok: str, want: set[str]) -> None:
    """[96] a short-option word yields its possible glued values, one after
    each letter of its leading run, never one per character."""
    assert gg_mod._glued_values({tok}) - {tok} == want
