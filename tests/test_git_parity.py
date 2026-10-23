"""gitguard <-> git consistency: what gitguard reads must be what git reads.

Every divergence where git honours a value gitguard does not see is a
detection bug. The tests take **git as the oracle** (`git config -f
--list -z`, `--type=path`, `rev-parse`, `ls-files -s`, `--show-origin`) and
check the inclusion "everything git sees, gitguard sees".

Environment assumption: `safe.bareRepository=explicit` in the global config.

Known divergences are marked `xfail(strict=True)`: the suite stays green, and
a fix makes the test fail (XPASS) so that the mark gets removed — then the
end-to-end scenario is moved into tests/attacks/.
"""
from __future__ import annotations

import getpass
import os
import subprocess
from pathlib import Path

import pytest

import gitguard as gg_mod
from gitguard import _expand2, global_config_files, index_gitlinks, object_id_size, parse_git_config
from tests.conftest import GG, write_exec

XF = pytest.mark.xfail
BENIGN = "#!/bin/sh\nexit 0\n"
EVIL = "#!/bin/sh\ntouch \"$HOME/PWNED\"\nexit 0\n"


def _git_list(p: Path) -> list[tuple[str, str]] | None:
    """Oracle: (key, value) as git reads them, None if git rejects the file."""
    r = subprocess.run(["git", "config", "-f", str(p), "--no-includes", "--list", "-z"],
                       capture_output=True, env={**os.environ, "LC_ALL": "C"})
    if r.returncode:
        return None
    out = []
    for rec in r.stdout.split(b"\0")[:-1]:
        k, nl, v = rec.partition(b"\n")
        out.append((k.decode(errors="surrogateescape"),
                    v.decode(errors="surrogateescape") if nl else "true"))
    return out


def _gg_list(p: Path) -> list[tuple[str, str]]:
    return [(f"{s}.{k}", v) for s, k, v in parse_git_config(p)]


# ================================================== 1. config parser vs git
# (name, file bytes). Everything git reads must be read identically.
PARSER_OK = [
    ("crlf", b"[core]\r\n\thooksPath = .githooks\r\n"),
    ("crlf_continuation", b"[core]\r\n\thooksPath = \\\r\n.githooks\r\n"),
    ("cr_only", b"[core]\r\thooksPath = .githooks\r"),
    # A lone CR inside a value is whitespace git keeps; text-mode reading made
    # it a line break (two keys instead of one, the real path unwatched). [52]
    ("cr_inside_value", b"[core]\n\thooksPath = .githooks\rx = y\n"),
    ("cr_inside_value_opts", b"[options]\n\tstrategy = ort\rx = /y\n"),
    ("old_style_subsection", b"[Core.Sub]\n\tX = 1\n"),
    ("old_style_branch", b"[branch.Main]\n\tremote = o\n"),
    ("subsection_case_kept", b'[Alias "X"]\n\tY = z\n'),
    ("tab_before_subsection", b'[core\t"x"]\n\tk=v\n'),
    ("key_on_header_line", b"[core]hooksPath = .githooks\n"),
    ("header_trailing_comment", b"[core]  ; c\n\thooksPath = .githooks\n"),
    ("empty_value", b"[core]\n\thooksPath =\n"),
    ("bool_no_value", b"[core]\n\tbare\n"),
    ("quoted_then_comment", b'[core]\n\thooksPath = ".githooks" # c\n'),
    ("hash_in_quotes", b'[alias]\n\tx = "!echo #no ;no"\n'),
    ("inline_comment", b"[alias]\n\tx = a#b\n\ty = c;d\n"),
    ("tabs_around_eq", b"[core]\n\thooksPath\t=\t.githooks\n"),
    ("dash_in_key", b"[core]\n\thooks-Path = x\n"),
    ("escapes", b'[alias]\n\tx = "a\\tb\\nc\\\\d\\"e"\n'),
    ("continuation_in_quotes", b'[alias]\n\tx = "a \\\n  b"\n'),
    ("even_backslashes", b"[alias]\n\tx = foo\\\\\n\ty = bar\n"),
    ("non_utf8", b"[alias]\n\tx = \xff\xfe\n[core]\n\thooksPath = .githooks\n"),
    ("include_case", b"[INCLUDE]\n\tPATH = a\n[IncludeIf \"gitdir:/X/\"]\n\tpath = b\n"),
    ("duplicate_keys", b"[core]\n\thooksPath = a\n[core]\n\thooksPath = b\n"),
    # Formerly divergent (xfail), fixed by the port of git's parser [46]:
    ("utf8_bom", b"\xef\xbb\xbf[core]\n\thooksPath = .githooks\n"),
    ("comment_line_backslash_hash", b"[core]\n# note \\\n\thooksPath = .githooks\n"),
    ("comment_line_backslash_semi", b"[core]\n; note \\\n\thooksPath = .githooks\n"),
    ("inline_comment_backslash_hash", b"[core]\n\tpager = less # x \\\n\thooksPath = .githooks\n"),
    ("inline_comment_backslash_semi", b"[core]\n\tpager = less ; x \\\n\thooksPath = .githooks\n"),
    ("backslash_at_eof", b"[core]\n\thooksPath = .githooks\\"),
    ("internal_whitespace", b"[core]\n\thooksPath = my  \thooks\n"),
    ("subsection_unknown_escape", b'[a "b\\\\c\\"d\\e"]\n\tk = v\n'),
    ("vertical_tab_value", b"[core]\n\thooksPath =\x0b.githooks\n"),
    ("nbsp_trailing", "[core]\n\thooksPath = .githooks\u00a0\n".encode()),
    ("trailing_space_then_comment", b"[core]\n\thooksPath = .githooks   # c\n"),
    ("quoted_then_space", b'[core]\n\thooksPath = "a b"  \n'),
]

# Files git rejects (fatal: bad config line): gitguard's tolerance is harmless
# as long as git rejects. If a git version accepts them, this test fails: one
# must then check that gitguard reads the same thing.
GIT_REJECTS = [
    ("key_then_comment", b"[core]\n\tbare # c\n"),
    ("spaces_in_brackets", b"[ core ]\n\thooksPath = .githooks\n"),
    ("header_continuation", b"[core] \\\n\thooksPath = .githooks\n"),
    ("formfeed_before_header", b"\x0c[core]\n\thooksPath = .githooks\n"),
    ("unknown_value_escape", b"[core]\n\tpager = a\\qb\n"),
    ("unterminated_quote", b'[core]\n\tpager = "a\n'),
]


def _assert_parser_covers_git(tmp_path: Path, data: bytes) -> None:
    p = tmp_path / "cfg"
    p.write_bytes(data)
    want = _git_list(p)
    assert want is not None, "git rejects this file: move the case to GIT_REJECTS"
    got = _gg_list(p)
    missing = [kv for kv in want if kv not in got]
    assert not missing, f"git reads {missing}, gitguard reads {got}"


@pytest.mark.parametrize("data", [c[1] for c in PARSER_OK], ids=[c[0] for c in PARSER_OK])
def test_parser_matches_git(tmp_path: Path, data: bytes) -> None:
    _assert_parser_covers_git(tmp_path, data)


def test_parser_nul_refused(tmp_path: Path) -> None:
    """git truncates a value at a NUL byte (C string); gitguard refuses the
    file instead of guessing — see test_nul_in_config_fails_closed."""
    p = tmp_path / "cfg"
    p.write_bytes(b"[core]\n\thooksPath = .githooks\x00junk\n")
    assert _git_list(p) == [("core.hookspath", ".githooks")]
    with pytest.raises(gg_mod.Refuse):
        parse_git_config(p)


@pytest.mark.parametrize("data", [c[1] for c in GIT_REJECTS], ids=[c[0] for c in GIT_REJECTS])
def test_parser_refuses_what_git_rejects(tmp_path: Path, data: bytes) -> None:
    """Same port, same verdict: a file git dies on is refused (not silently
    read differently)."""
    p = tmp_path / "cfg"
    p.write_bytes(data)
    with pytest.raises(gg_mod.Refuse):
        parse_git_config(p)


@pytest.mark.parametrize("data", [c[1] for c in GIT_REJECTS], ids=[c[0] for c in GIT_REJECTS])
def test_git_still_rejects(tmp_path: Path, data: bytes) -> None:
    p = tmp_path / "cfg"
    p.write_bytes(data)
    assert _git_list(p) is None, "git now accepts this file: compare with gitguard"


# ---- end to end: git honours core.hooksPath ⇒ gitguard watches .githooks
def _hookspath_e2e(gg: GG, repo: Path, edit) -> None:
    write_exec(repo / ".githooks/pre-commit", BENIGN)
    cfg = repo / ".git/config"
    cfg.write_bytes(edit(cfg.read_bytes()))
    r = gg.git("config", "--get", "core.hookspath", cwd=repo)
    assert r.out.strip() == ".githooks", f"precondition: git must honour hooksPath\n{r.text}"
    gg.trust(repo)
    write_exec(repo / ".githooks/pre-commit", EVIL)
    r = gg.check(repo)
    assert r.blocked, f"rewritten hook accepted although git will execute it\n{r.text}"


E2E_PARSER = [
    # the BOM must precede the section carrying the key: gitguard loses that section
    ("utf8_bom", lambda b: b"\xef\xbb\xbf[core]\n\thooksPath = .githooks\n" + b),
    ("comment_line_backslash", lambda b: b + b"[core]\n# husky \\\n\thooksPath = .githooks\n"),
    ("inline_comment_backslash", lambda b: b + b"[core]\n\tpager = less # x \\\n\thooksPath = .githooks\n"),
    ("backslash_at_eof", lambda b: b + b"[core]\n\thooksPath = .githooks\\"),
]


def test_hookspath_e2e_control(gg: GG, repo: Path) -> None:
    """Control: the ordinary form is detected (the harness can succeed)."""
    _hookspath_e2e(gg, repo, lambda b: b + b"[core]\n\thooksPath = .githooks\n")


@pytest.mark.parametrize("edit", [c[1] for c in E2E_PARSER], ids=[c[0] for c in E2E_PARSER])
def test_hookspath_e2e_parser_cases(gg: GG, repo: Path, edit) -> None:
    """Formerly divergent [46]: git honours the hooksPath, so must gitguard."""
    _hookspath_e2e(gg, repo, edit)


def test_nul_in_config_fails_closed(gg: GG, repo: Path) -> None:
    """NUL in a value: git truncates, gitguard keeps the byte — but lstat()
    raises ValueError, hence an internal error and a (closed) refusal, at
    trust as at check time. Keep it closed if the parser gets fixed."""
    write_exec(repo / ".githooks/pre-commit", BENIGN)
    cfg = repo / ".git/config"
    cfg.write_bytes(cfg.read_bytes() + b"[core]\n\thooksPath = .githooks\x00\n")
    assert gg.git("config", "--get", "core.hookspath", cwd=repo).out.strip() == ".githooks"
    assert gg.run("trust", cwd=repo).blocked
    assert gg.check(repo).blocked


# ================================================ 2. path expansion vs git
def _git_path(tmp_path: Path, value: str, env: dict) -> str | None:
    p = tmp_path / "pcfg"
    p.write_text(f"[x]\n\tp = {value}\n")
    r = subprocess.run(["git", "config", "-f", str(p), "--type=path", "--get", "x.p"],
                       capture_output=True, text=True, env=env)
    return r.stdout.rstrip("\n") if r.returncode == 0 else None


@pytest.mark.parametrize("value", [
    "~/x",
    "/abs/x",
    pytest.param(f"~{getpass.getuser()}/x", id="tilde_user"),   # [50]
    pytest.param(f"~{getpass.getuser()}", id="tilde_user_bare"),
    "~",
])
def test_path_expansion_matches_git(gg: GG, tmp_path: Path, monkeypatch, value: str) -> None:
    monkeypatch.setenv("HOME", gg.env["HOME"])
    want = _git_path(tmp_path, value, gg.env)
    assert want is not None and os.path.isabs(want)
    literal, _ = _expand2(value, tmp_path / "root")
    assert str(literal) == want


# ================================================ 3. includes: what git follows
def test_include_relative_to_global_config(gg: GG, repo: Path) -> None:
    """Relative include.path in ~/.gitconfig: relative to $HOME for git."""
    home = Path(gg.env["HOME"])
    (home / "inc.cfg").write_text("[core]\n")
    gg.git("config", "--global", "include.path", "inc.cfg")
    gg.trust(repo)
    (home / "inc.cfg").write_text("[core]\n\tfsmonitor = /tmp/evil\n")
    assert gg.git("config", "--get", "core.fsmonitor", cwd=repo).out.strip() == "/tmp/evil"
    assert gg.check(repo).blocked


def test_include_nested_relative_to_including_file(gg: GG, repo: Path) -> None:
    """An include inside an included file is relative to THAT file's directory."""
    (repo / "cfg").mkdir()
    (repo / "cfg/a.cfg").write_text("[include]\n\tpath = b.cfg\n")
    (repo / "cfg/b.cfg").write_text("[core]\n")
    gg.git("config", "include.path", "../cfg/a.cfg", cwd=repo)
    gg.trust(repo)
    (repo / "cfg/b.cfg").write_text("[core]\n\tfsmonitor = /tmp/evil\n")
    assert gg.git("config", "--get", "core.fsmonitor", cwd=repo).out.strip() == "/tmp/evil"
    assert gg.check(repo).blocked


def test_include_missing_then_created(gg: GG, repo: Path) -> None:
    """include.path to an optional file absent at trust time, created afterwards."""
    gg.git("config", "include.path", "../local.cfg", cwd=repo)
    gg.trust(repo)
    (repo / "local.cfg").write_text("[core]\n\tfsmonitor = /tmp/evil\n")
    assert gg.git("config", "--get", "core.fsmonitor", cwd=repo).out.strip() == "/tmp/evil"
    assert gg.check(repo).blocked


@pytest.mark.parametrize("cond", ["onbranch:main", "gitdir:/", "gitdir/i:/",
                                  "hasconfig:remote.*.url:**"])
def test_includeif_any_condition_followed(gg: GG, repo: Path, cond: str) -> None:
    gg.git("remote", "add", "origin", "https://example.invalid/x", cwd=repo)
    (repo / "if.cfg").write_text("[core]\n")
    gg.git("config", f"includeIf.{cond}.path", "../if.cfg", cwd=repo)
    gg.trust(repo)
    (repo / "if.cfg").write_text("[core]\n\tfsmonitor = /tmp/evil\n")
    assert gg.git("config", "--get", "core.fsmonitor", cwd=repo).out.strip() == "/tmp/evil"
    assert gg.check(repo).blocked


# ======================= 4. value tokens vs what sh actually executes
# Alias value (without the `!`) → git hands it to sh. If the tree script it
# launches is not recognised as a path, its rewrite goes through.
SHELL_OK = ["./tool.sh", "sh tool.sh", "sh -c ./tool.sh", '"./tool.sh"',
            # sh operators: split since [37] (were xfail)
            "./tool.sh&&true", "./tool.sh|cat", "sh<tool.sh", "(./tool.sh)",
            "echo $(./tool.sh)", "f() { ./tool.sh; }; f", "./tool.sh;true",
            # sh expansions at the top of the tree [37]
            "$PWD/tool.sh", "${PWD}/tool.sh", "$(git rev-parse --show-toplevel)/tool.sh",
            "T=./tool.sh; $T"]


def _alias_e2e(gg: GG, repo: Path, cmd: str) -> None:
    mark = Path(gg.env["HOME"]) / "RAN"
    write_exec(repo / "tool.sh", f"#!/bin/sh\ntouch '{mark}'\n")
    esc = ("!" + cmd).replace("\\", "\\\\").replace('"', '\\"')
    cfg = repo / ".git/config"
    cfg.write_text(cfg.read_text() + f'[alias]\n\tt = "{esc}"\n')
    gg.git("t", cwd=repo)
    assert mark.exists(), "precondition: git does execute tool.sh through this alias"
    gg.trust(repo)
    write_exec(repo / "tool.sh", EVIL)
    r = gg.check(repo)
    assert r.blocked, f"rewritten tool.sh accepted although `git t` executes it\n{r.text}"


# sh expansions expandvars does not perform: git (sh) runs tool.sh, gitguard
# saw no path. [58]
SHELL_EXPANSIONS = ["${TOOL:-./tool.sh}", "${TOOL-./tool.sh}", "${PWD:+./tool.sh}",
              '"${TOOL:-./tool.sh}"', "$(pwd)/tool.sh", "`pwd`/tool.sh",
              "./tool.sh${OPT:+ x}", "sh -c '${T:-./tool.sh}'",
              "$( pwd )/tool.sh", "$(pwd -P)/tool.sh", '"$(pwd)"/tool.sh',
              "${A:=./tool.sh}", "${A:-${B:-./tool.sh}}", "$(echo .)/tool.sh",
              "`echo ./tool.sh`", "${A:-.}/tool.sh", "x=$(pwd); $x/tool.sh",
              "f() { $1/tool.sh; }; f .", "cd $(pwd) && ./tool.sh",
              "$(dirname $(pwd)/x)/tool.sh", "${HOME:+$(pwd)}/tool.sh"]


@pytest.mark.parametrize("cmd", SHELL_OK + SHELL_EXPANSIONS)
def test_alias_script_watched(gg: GG, repo: Path, cmd: str) -> None:
    _alias_e2e(gg, repo, cmd)


# ====================================== 5. repository discovery vs git rev-parse
def _git_view(gg: GG, cwd: Path) -> tuple[Path, Path] | None:
    r = gg.git("rev-parse", "--show-toplevel", "--absolute-git-dir", cwd=cwd)
    if r.rc:
        return None
    top, gd = r.out.splitlines()
    return Path(top).resolve(), Path(gd).resolve()


def _gg_view(cwd: Path, monkeypatch) -> tuple[Path, Path] | None:
    """(root, gitdir) chosen by gitguard; None if it refuses."""
    monkeypatch.delenv("GIT_DIR", raising=False)
    try:
        root = gg_mod.find_root(cwd)
        if root is None:
            return None
        repo = gg_mod.open_repo(root)
    except gg_mod.Refuse:
        return None
    return repo.root, repo.gitdir


def _assert_same_repo(gg: GG, cwd: Path, monkeypatch) -> None:
    want = _git_view(gg, cwd)
    got = _gg_view(cwd, monkeypatch)
    if got is None:
        return                       # gitguard refuses: safe whatever git does
    assert want is not None and got == want, f"git uses {want}, gitguard checks {got}"


@pytest.fixture
def explicit(gg: GG) -> GG:
    assert gg.git("config", "--global", "safe.bareRepository", "explicit").rc == 0
    return gg


@pytest.mark.discovery
def test_discovery_subdir(explicit: GG, repo: Path, monkeypatch) -> None:
    (repo / "a/b").mkdir(parents=True)
    _assert_same_repo(explicit, repo / "a/b", monkeypatch)


@pytest.mark.discovery
def test_discovery_linked_worktree(explicit: GG, repo: Path, tmp_path: Path, monkeypatch) -> None:
    assert explicit.git("worktree", "add", "-q", str(tmp_path / "wt"), cwd=repo).rc == 0
    _assert_same_repo(explicit, tmp_path / "wt", monkeypatch)


@pytest.mark.discovery
def test_discovery_invalid_dotgit_dir_skipped_by_git(explicit: GG, repo: Path, monkeypatch) -> None:
    """[49] `.git` directory invalid for git (no HEAD/objects/refs): git
    ignores it and walks up to the parent; gitguard stopped on it."""
    (repo / "src/.git").mkdir(parents=True)
    (repo / "src/.git/config").write_text("[core]\n")
    _assert_same_repo(explicit, repo / "src", monkeypatch)


@pytest.mark.parametrize("layout", ["head_symlink", "commondir", "commondir_nul", "head_sha",
                                    "head_ref_tab"])
@pytest.mark.discovery
def test_discovery_gitdir_variants_match_git(explicit: GG, repo: Path, tmp_path: Path,
                                             monkeypatch, layout: str) -> None:
    """[49] is_git_directory as git has it: HEAD may be a symlink to refs/…,
    a detached SHA, `ref:<tab>refs/…`; objects/refs may live behind `commondir`."""
    g = repo / "src/.git"
    g.mkdir(parents=True)
    (g / "config").write_text("[core]\n")
    if layout.startswith("commondir"):
        (g / "HEAD").write_text("ref: refs/heads/main\n")
        # NUL: git truncates (C string) and still finds the common dir. [53]
        (g / "commondir").write_bytes(b"../../.git\n" if layout == "commondir"
                                      else b"../../.git\0junk\n")
    else:
        (g / "objects").mkdir(); (g / "refs").mkdir()
        if layout == "head_symlink":
            (g / "HEAD").symlink_to("refs/heads/nope")
        elif layout == "head_sha":
            (g / "HEAD").write_text("0" * 40 + "\n")
        else:
            (g / "HEAD").write_text("ref:\trefs/heads/main\n")
    _assert_same_repo(explicit, repo / "src", monkeypatch)


# [53] Files git reads as ONE path: the gitfile (`gitdir: <path>`) and
# `commondir`. git trims every trailing CR/LF and nothing else; a blank, a lone
# CR or a second line are part of the path, git finds no repository and dies.
# gitguard read them with splitlines()/strip() and a lexical resolve(): it
# checked a repository git never opens. Strict here: same verdict both ways.
PATH_FILE_VARIANTS = [
    ("plain", b"{p}\n", True), ("crlf", b"{p}\r\n", True), ("no_newline", b"{p}", True),
    ("two_newlines", b"{p}\n\n", True), ("cr_only_end", b"{p}\r", True),
    ("trailing_space", b"{p} \n", False), ("trailing_tab", b"{p}\t\n", False),
    ("lone_cr_inside", b"{p}\rx\n", False), ("second_line", b"{p}\nx\n", False),
    ("leading_space", b" {p}\n", False),
]


def _same_verdict(gg: GG, cwd: Path, monkeypatch, git_accepts: bool) -> None:
    want, got = _git_view(gg, cwd), _gg_view(cwd, monkeypatch)
    assert (want is not None) == git_accepts, f"git's own behaviour changed: {want}"
    assert got == want, f"git uses {want}, gitguard checks {got}"


@pytest.mark.parametrize("fmt,git_accepts", [c[1:] for c in PATH_FILE_VARIANTS],
                         ids=[c[0] for c in PATH_FILE_VARIANTS])
@pytest.mark.discovery
def test_gitfile_read_like_git(explicit: GG, repo: Path, tmp_path: Path, monkeypatch,
                               fmt: bytes, git_accepts: bool) -> None:
    wt = tmp_path / "wt"
    assert explicit.git("worktree", "add", "-q", str(wt), cwd=repo).rc == 0
    target = str(repo / ".git/worktrees/wt").encode()
    (wt / ".git").write_bytes(b"gitdir: " + fmt.replace(b"{p}", target))
    _same_verdict(explicit, wt, monkeypatch, git_accepts)


@pytest.mark.parametrize("fmt,git_accepts", [c[1:] for c in PATH_FILE_VARIANTS],
                         ids=[c[0] for c in PATH_FILE_VARIANTS])
@pytest.mark.discovery
def test_commondir_read_like_git(explicit: GG, repo: Path, tmp_path: Path, monkeypatch,
                                 fmt: bytes, git_accepts: bool) -> None:
    wt = tmp_path / "wt"
    assert explicit.git("worktree", "add", "-q", str(wt), cwd=repo).rc == 0
    (repo / ".git/worktrees/wt/commondir").write_bytes(fmt.replace(b"{p}", b"../.."))
    _same_verdict(explicit, wt, monkeypatch, git_accepts)


# ============================================ rebase todo: `exec` as git reads it
# (name, bytes prepended to git-rebase-todo, does git run the line). The rule
# is one-way: whenever git runs it, gitguard must refuse; a refusal where git
# does nothing is a false positive we accept (fail closed). git's own column is
# asserted too, so that a git version changing what it runs is seen here.
# Checked with git 2.47.3 (Debian) and 2.50.0 (Homebrew). [35] [53]
TODO_EXEC_VARIANTS = [
    ("plain", b"exec {c}\n", True),
    ("crlf", b"exec {c}\r\n", True),
    ("tab_after_word", b"exec\t{c}\n", True),
    ("leading_tab", b"\texec {c}\n", True),
    ("leading_spaces", b"  exec {c}\n", True),
    ("x_nickname", b"x {c}\n", True),
    ("leading_cr", b"\rexec {c}\n", False),
    ("leading_vt", b"\vexec {c}\n", False),
    ("cr_after_word", b"exec\r{c}\n", False),
    ("cr_mid_line", b"noop\rexec {c}\n", False),
    ("after_nul", b"noop\0\nexec {c}\n", False),
    ("upper_case", b"EXEC {c}\n", False),
]


@pytest.mark.parametrize("fmt,git_runs", [c[1:] for c in TODO_EXEC_VARIANTS],
                         ids=[c[0] for c in TODO_EXEC_VARIANTS])
def test_todo_exec_seen_whenever_git_runs_it(gg: GG, repo: Path, tmp_path: Path,
                                             fmt: bytes, git_runs: bool) -> None:
    from tests.attacks.tool_itself import _interrupted_rebase
    todo = _interrupted_rebase(gg, repo, tmp_path)
    gg.trust(repo)
    marker = Path(gg.env["HOME"]) / "PWNED"
    cmd = f'touch "{marker}"'.encode()
    todo.write_bytes(fmt.replace(b"{c}", cmd) + todo.read_bytes())
    refused = gg.check(repo).blocked              # before git consumes the todo
    subprocess.run(["git", "rebase", "--continue"], cwd=repo, capture_output=True,
                   env={**gg.env, "GIT_EDITOR": "true"})
    ran = marker.exists()
    assert ran == git_runs, f"git's own behaviour changed: ran={ran}"
    if ran:
        assert refused, "git ran the exec line and gitguard had let it through"


@pytest.mark.parametrize("layout", ["commondir", "head_symlink_unborn", "full_bare"])
@pytest.mark.discovery
def test_planted_gitdir_refused_by_git_with_explicit(explicit: GG, repo: Path, layout: str) -> None:
    """Bare-gitdir variants that is_bare_gitdir does not recognise (commondir,
    dangling HEAD symlink): the safe.bareRepository=explicit assumption must
    make git itself refuse. If this test breaks, find_root must learn them."""
    src = repo / "src"
    src.mkdir()
    (src / "config").write_text("[core]\n\tfsmonitor = touch /tmp/x\n")
    if layout == "commondir":
        (src / "HEAD").write_text("ref: refs/heads/main\n")
        (src / "commondir").write_text("../.git\n")
    elif layout == "head_symlink_unborn":
        (src / "objects").mkdir(); (src / "refs").mkdir()
        (src / "HEAD").symlink_to("refs/heads/nope")
    else:
        (src / "objects").mkdir(); (src / "refs").mkdir()
        (src / "HEAD").write_text("ref: refs/heads/main\n")
    r = explicit.git("rev-parse", "--absolute-git-dir", cwd=src)
    assert r.rc != 0 or Path(r.out.strip()).resolve() == (repo / ".git").resolve(), r.text


@pytest.mark.discovery
def test_core_worktree_hookspath(explicit: GG, repo: Path, tmp_path: Path) -> None:
    """[47] core.worktree in .git/config: git takes that directory as the root
    and resolves a relative core.hooksPath there."""
    other = tmp_path / "other"
    write_exec(other / ".githooks/pre-commit", BENIGN)
    explicit.git("config", "core.worktree", str(other), cwd=repo)
    explicit.git("config", "core.hooksPath", ".githooks", cwd=repo)
    assert explicit.git("rev-parse", "--show-toplevel", cwd=repo).out.strip() == str(other.resolve())
    explicit.run("trust", cwd=repo)
    write_exec(other / ".githooks/pre-commit", EVIL)
    assert explicit.check(repo).blocked


@pytest.mark.parametrize("where", ["common", "common_with_extension", "config_worktree"])
@pytest.mark.discovery
def test_core_worktree_in_a_linked_worktree_as_git(explicit: GG, repo: Path, tmp_path: Path,
                                                   where: str) -> None:
    """[76] check_repository_format_gently applies core.worktree only `if
    (!has_common)`: never in a linked worktree — unless
    extensions.worktreeConfig, which reads this gitdir's config.worktree
    (its value wins) and clears has_common. Git says where the tree is,
    open_repo must agree, and the worktree stays trustable."""
    wt, other = tmp_path / "wt", tmp_path / "other"
    other.mkdir()
    assert explicit.git("worktree", "add", "-q", str(wt), cwd=repo).rc == 0
    if where != "common":
        explicit.git("config", "extensions.worktreeConfig", "true", cwd=repo)
    if where == "config_worktree":
        assert explicit.git("config", "--worktree", "core.worktree", str(other), cwd=wt).rc == 0
    else:
        explicit.git("config", "core.worktree", str(other), cwd=repo)
    top = Path(explicit.git("rev-parse", "--show-toplevel", cwd=wt).out.strip()).resolve()
    assert top == (wt if where == "common" else other).resolve(), where
    assert gg_mod.open_repo(wt).root.resolve() == top
    assert explicit.run("trust", cwd=wt).rc == 0


# ========================================= 6. index gitlinks vs ls-files -s
def _git_gitlinks(gg: GG, repo: Path) -> list[str]:
    r = subprocess.run(["git", "ls-files", "-s", "-z"], cwd=repo, env=gg.env, capture_output=True)
    out = []
    for rec in r.stdout.split(b"\0"):
        if rec.startswith(b"160000 "):
            out.append(rec.split(b"\t", 1)[1].decode(errors="surrogateescape"))
    return sorted(out)


@pytest.mark.parametrize("fmt", ["sha1", "sha256"])
@pytest.mark.parametrize("skiphash", [False, True], ids=["hash", "skipHash"])
@pytest.mark.parametrize("version", [2, 3, 4])
def test_index_gitlinks_match_ls_files(gg: GG, repo: Path, tmp_path: Path, version: int,
                                       skiphash: bool, fmt: str) -> None:
    """…in both object formats: the entries of a SHA-256 index hold 32-byte
    ids, the parser assumed 20 and refused every one as forged. [63]"""
    if fmt == "sha256":
        repo = tmp_path / "s256"
        assert gg.git("init", "-q", "--object-format=sha256", str(repo)).rc == 0
        (repo / "f").write_text("a\n")
        gg.git("add", "f", cwd=repo)
        assert gg.git("commit", "-qm", "i", cwd=repo).rc == 0
    sha = gg.git("rev-parse", "HEAD", cwd=repo).out.strip()
    long = "/".join(["d" * 200] * 25) + "/sub"          # > 0xFFF: saturated name length
    paths = ["vendor/a", "vendor/ab", "node_modules/pkg", "é space/x", long, "z"]
    (repo / "ita").write_text("x\n")
    pre = ["-c", "index.skipHash=true"] if skiphash else []
    assert gg.git(*pre, "add", "-N", "ita", cwd=repo).rc == 0       # extended entry (v3+)
    for p in paths:
        r = gg.git(*pre, "update-index", "--add", "--cacheinfo", f"160000,{sha},{p}", cwd=repo)
        assert r.rc == 0, r.text
    assert gg.git(*pre, "update-index", "--index-version", str(version), cwd=repo).rc == 0
    want = _git_gitlinks(gg, repo)
    assert len(want) == len(paths)
    assert sorted(index_gitlinks(repo / ".git/index", None, object_id_size(repo / ".git"))) == want


# Repository format as git reads it (check_repository_format): config text
# of the gitdir -> must git open the repository. [63]
OBJECT_FORMAT_VARIANTS = {
    "v1_sha256": "[core]\n\trepositoryformatversion = 1\n[extensions]\n\tobjectformat = sha256\n",
    "v1_sha1": "[core]\n\trepositoryformatversion = 1\n[extensions]\n\tobjectformat = sha1\n",
    "v1_none": "[core]\n\trepositoryformatversion = 1\n",
    "v0_sha256": "[core]\n\trepositoryformatversion = 0\n[extensions]\n\tobjectformat = sha256\n",
    "no_version_sha256": "[extensions]\n\tobjectformat = sha256\n",
    "v2_sha256": "[core]\n\trepositoryformatversion = 2\n[extensions]\n\tobjectformat = sha256\n",
    "v01_sha256": "[core]\n\trepositoryformatversion = 01\n[extensions]\n\tobjectformat = sha256\n",
    "v0x1_sha256": "[core]\n\trepositoryformatversion = 0x1\n[extensions]\n\tobjectformat = sha256\n",
    "v1k_sha256": "[core]\n\trepositoryformatversion = 1k\n[extensions]\n\tobjectformat = sha256\n",
    "v08_sha256": "[core]\n\trepositoryformatversion = 08\n[extensions]\n\tobjectformat = sha256\n",
    "v_quoted_blank": "[core]\n\trepositoryformatversion = \"1 \"\n[extensions]\n\tobjectformat = sha256\n",
    "v_leading_tab": "[core]\n\trepositoryformatversion = \"\t1\"\n[extensions]\n\tobjectformat = sha256\n",
    "v_negative": "[core]\n\trepositoryformatversion = -1\n[extensions]\n\tobjectformat = sha256\n",
    "v_minus2": "[core]\n\trepositoryformatversion = -2\n[extensions]\n\tobjectformat = sha256\n",
    "v_minus0": "[core]\n\trepositoryformatversion = -0\n[extensions]\n\tobjectformat = sha256\n",
    "v_empty": "[core]\n\trepositoryformatversion =\n[extensions]\n\tobjectformat = sha256\n",
    "upper_SHA256": "[core]\n\trepositoryformatversion = 1\n[extensions]\n\tobjectformat = SHA256\n",
    "quoted_blank": "[core]\n\trepositoryformatversion = 1\n[extensions]\n\tobjectformat = \"sha256 \"\n",
    "valueless": "[core]\n\trepositoryformatversion = 1\n[extensions]\n\tobjectformat\n",
    "empty": "[core]\n\trepositoryformatversion = 1\n[extensions]\n\tobjectformat =\n",
    "last_wins_sha1": "[core]\n\trepositoryformatversion = 1\n[extensions]\n\tobjectformat = sha256\n\tobjectformat = sha1\n",
    "last_wins_sha256": "[core]\n\trepositoryformatversion = 1\n[extensions]\n\tobjectformat = sha1\n\tobjectformat = sha256\n",
    "mixed_case_key": "[CORE]\n\tRepositoryFormatVersion = 1\n[Extensions]\n\tObjectFormat = sha256\n",
    "via_include": "[core]\n\trepositoryformatversion = 1\n[include]\n\tpath = inc\n",
    # an invalid value makes git die as it reads it, whatever the version
    # and whatever follows: "last value wins" does not apply
    "md5_then_sha256": "[core]\n\trepositoryformatversion = 1\n[extensions]\n\tobjectformat = md5\n\tobjectformat = sha256\n",
    "no_version_md5": "[extensions]\n\tobjectformat = md5\n",
    "no_version_valueless": "[extensions]\n\tobjectformat\n",
    "v_minus1_md5": "[core]\n\trepositoryformatversion = -1\n[extensions]\n\tobjectformat = md5\n",
    "title_case": "[core]\n\trepositoryformatversion = 1\n[extensions]\n\tobjectformat = Sha256\n",
}


@pytest.mark.parametrize("name", OBJECT_FORMAT_VARIANTS)
def test_object_format_as_git_reads_it(gg: GG, tmp_path: Path, name: str) -> None:
    from gitguard import Refuse
    r = tmp_path / "s256"
    assert gg.git("init", "-q", "--object-format=sha256", str(r)).rc == 0
    (r / ".git/inc").write_text("[extensions]\n\tobjectformat = sha256\n")
    (r / ".git/config").write_text(OBJECT_FORMAT_VARIANTS[name])
    oracle = gg.git("rev-parse", "--show-object-format", cwd=r)
    try:
        got = object_id_size(r / ".git")
    except Refuse:
        got = None
    if oracle.rc:
        assert got is None, f"git refuses the repository ({oracle.err.strip()}), gitguard reads {got}"
    else:
        assert got == {"sha1": 20, "sha256": 32}[oracle.out.strip()], (oracle.out, got)


# ======================== 7. system/global config files that git reads
def _git_origins(env: dict, cwd: Path) -> set[Path]:
    r = subprocess.run(["git", "config", "--list", "--show-origin", "-z"], cwd=cwd, env=env,
                       capture_output=True)
    out = set()
    for rec in r.stdout.split(b"\0")[0::2]:
        if rec.startswith(b"file:"):
            out.add(Path(rec[5:].decode()).resolve())
    return out


@pytest.mark.parametrize("variant", ["default", "xdg", "git_config_global", "git_config_system"])
def test_global_config_files_cover_git(gg: GG, tmp_path: Path, monkeypatch, variant: str) -> None:
    home = Path(gg.env["HOME"])
    env = dict(gg.env)
    (home / ".config/git").mkdir(parents=True)
    (home / ".config/git/config").write_text("[a]\n\tb = 1\n")
    if variant == "xdg":
        env["XDG_CONFIG_HOME"] = str(tmp_path / "xdg")
        (tmp_path / "xdg/git").mkdir(parents=True)
        (tmp_path / "xdg/git/config").write_text("[a]\n\tc = 1\n")
    if variant == "git_config_global":
        env["GIT_CONFIG_GLOBAL"] = str(tmp_path / "g.cfg")
        (tmp_path / "g.cfg").write_text("[a]\n\td = 1\n")
    if variant == "git_config_system":
        env.pop("GIT_CONFIG_NOSYSTEM")
        env["GIT_CONFIG_SYSTEM"] = str(tmp_path / "s.cfg")
        (tmp_path / "s.cfg").write_text("[a]\n\te = 1\n")
    for k in ("XDG_CONFIG_HOME", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM"):
        monkeypatch.delenv(k, raising=False)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    want = _git_origins(env, tmp_path)
    assert want, "git reads no file: broken harness"
    got = {p.resolve() for p in global_config_files()}
    assert want <= got, f"git reads {want - got}, which gitguard does not parse"


def test_system_config_of_real_git_is_read(tmp_path: Path, monkeypatch) -> None:
    """The system config git actually uses must be among the files gitguard
    parses (Debian: /etc/gitconfig; Homebrew: /opt/homebrew/etc/gitconfig,
    derived from the git binary's prefix without asking git)."""
    monkeypatch.delenv("GIT_CONFIG_SYSTEM", raising=False)
    monkeypatch.delenv("GITGUARD_REAL_GIT", raising=False)
    real = gg_mod.real_git()
    env = {k: v for k, v in os.environ.items()
           if k not in ("GIT_CONFIG_SYSTEM", "GIT_CONFIG_NOSYSTEM")}
    env["GIT_EDITOR"] = "echo"
    r = subprocess.run([real, "config", "--system", "--edit"], cwd=tmp_path, env=env,
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    want = Path(r.stdout.strip()).resolve()
    got = {p.resolve() for p in global_config_files()}
    assert want in got, f"git uses {want}, gitguard reads {sorted(map(str, got))}"


@pytest.mark.parametrize("how", ["count", "parameters", "parameters_old", "dash_c"])
def test_env_config_hookspath(gg: GG, repo: Path, how: str) -> None:
    """[48] GIT_CONFIG_COUNT/KEY_n/VALUE_n, GIT_CONFIG_PARAMETERS (both
    syntaxes) and `-c`: git honours them, so does config_refs."""
    if how == "count":
        gg.env.update(GIT_CONFIG_COUNT="1", GIT_CONFIG_KEY_0="core.hooksPath",
                      GIT_CONFIG_VALUE_0=".githooks")
    elif how == "parameters":
        gg.env["GIT_CONFIG_PARAMETERS"] = "'user.x'='a b' 'core.hooksPath'='.githooks'"
    elif how == "parameters_old":
        gg.env["GIT_CONFIG_PARAMETERS"] = "'core.hooksPath=.githooks'"
    else:
        write_exec(repo / ".githooks/pre-commit", BENIGN)
        gg.trust(repo)
        write_exec(repo / ".githooks/pre-commit", EVIL)
        r = gg.run("git", "-c", "core.hooksPath=.githooks", "status", cwd=repo)
        assert r.blocked and "On branch" not in r.out, r.text
        r = gg.run("git", "status", cwd=repo)
        assert not r.blocked, r.text        # without -c the hook is not git's
        return
    write_exec(repo / ".githooks/pre-commit", BENIGN)
    assert gg.git("config", "--get", "core.hookspath", cwd=repo).out.strip() == ".githooks"
    gg.trust(repo)
    write_exec(repo / ".githooks/pre-commit", EVIL)
    assert gg.check(repo).blocked


# ------------------------------------------------- discovery: where git stops
def _with_env(gg: GG, **extra: str) -> GG:
    return GG(env={**gg.env, **extra}, state=gg.state)


@pytest.mark.discovery
def test_ceiling_directories_stop_gitguard_where_git_stops(gg: GG, repo: Path) -> None:
    """GIT_CEILING_DIRECTORIES=<repo>: from <repo>/sub git does not enter <repo>
    and finds nothing. gitguard used to walk up anyway, check the repository
    git would not open, and refuse on it."""
    sub = repo / "sub"
    sub.mkdir()
    write_exec(repo / ".git/hooks/pre-commit")               # modified: a refusal if checked
    assert gg.check(repo).blocked
    g = _with_env(gg, GIT_CEILING_DIRECTORIES=str(repo))
    oracle = g.git("rev-parse", "--show-toplevel", cwd=sub)
    assert oracle.rc != 0 and "not a git repository" in oracle.err
    r = g.run("git", "rev-parse", "--show-toplevel", cwd=sub)
    assert "gitguard" not in r.err, r.err
    assert r.rc == oracle.rc and "not a git repository" in r.err
    assert g.run(cwd=sub).rc == 0 and not g.run(cwd=sub).blocked      # plain check: nothing here
    # the ceiling itself is not entered, but the cwd always is
    g2 = _with_env(gg, GIT_CEILING_DIRECTORIES=str(repo.parent))
    assert g2.git("rev-parse", "--show-toplevel", cwd=sub).rc == 0
    assert g2.run("git", "rev-parse", "--show-toplevel", cwd=sub).blocked      # found, modified: refused
    assert g2.git("rev-parse", "--show-toplevel", cwd=repo).rc == 0
    assert g2.run("git", "status", cwd=repo).blocked


@pytest.mark.discovery
def test_ceiling_entries_are_resolved_unless_after_an_empty_one(gg: GG, repo: Path, tmp_path: Path) -> None:
    sub = repo / "sub"
    sub.mkdir()
    link = tmp_path / "link-to-repo"
    os.symlink(repo, link)
    write_exec(repo / ".git/hooks/pre-commit")
    g = _with_env(gg, GIT_CEILING_DIRECTORIES=str(link))               # resolved → the repo: a ceiling
    assert g.git("rev-parse", cwd=sub).rc != 0
    assert not g.run("git", "rev-parse", cwd=sub).err.count("gitguard")
    g = _with_env(gg, GIT_CEILING_DIRECTORIES=os.pathsep + str(link))  # literal → no ancestor: no ceiling
    assert g.git("rev-parse", cwd=sub).rc == 0
    assert g.run("git", "rev-parse", cwd=sub).blocked



# ================= 8. repository-local environment variables vs git [54]
def _git_common_dir(gg: GG, cwd: Path) -> Path | None:
    r = gg.git("rev-parse", "--path-format=absolute", "--git-common-dir", cwd=cwd)
    return None if r.rc else Path(r.out.strip()).resolve()


def _gg_common_dir(cwd: Path) -> Path | None:
    try:
        root = gg_mod.find_root(cwd)
        return None if root is None else gg_mod.open_repo(root).common.resolve()
    except gg_mod.Refuse:
        return None


def _other_gitdir(repo: Path, tmp_path: Path) -> Path:
    import shutil
    other = tmp_path / "other"
    shutil.copytree(repo / ".git", other)
    with open(other / "config", "a") as f:
        f.write("[x]\n\tmarker = other\n")
    return other


@pytest.mark.parametrize("where", ["root", "subdir", "linked_worktree"])
@pytest.mark.discovery
def test_env_common_dir_is_the_common_dir(explicit: GG, repo: Path, tmp_path: Path,
                                          monkeypatch, where: str) -> None:
    """GIT_COMMON_DIR (absolute): git reads config and hooks there, in a
    linked worktree too (its `commondir` file is ignored). gitguard must
    parse and fingerprint that directory, not the gitdir's own files."""
    other = _other_gitdir(repo, tmp_path)
    if where == "linked_worktree":
        assert explicit.git("worktree", "add", "-q", str(tmp_path / "wt"), cwd=repo).rc == 0
        cwd = tmp_path / "wt"
    else:
        cwd = repo if where == "root" else repo / "a/b"
        cwd.mkdir(parents=True, exist_ok=True)
    explicit.env["GIT_COMMON_DIR"] = str(other)
    monkeypatch.setenv("GIT_COMMON_DIR", str(other))
    assert explicit.git("config", "x.marker", cwd=cwd).out.strip() == "other"   # oracle
    want, got = _git_common_dir(explicit, cwd), _gg_common_dir(cwd)
    assert want == other.resolve() and got == want, f"git uses {want}, gitguard {got}"
    # And the config git honours is the one gitguard parses: a hooksPath
    # written there into the tree is watched.
    explicit.env.pop("GIT_COMMON_DIR")
    explicit.trust(repo)
    explicit.env["GIT_COMMON_DIR"] = str(other)
    r = explicit.check(repo)
    assert r.blocked and "common" in r.text, r.text


@pytest.mark.discovery
def test_env_common_dir_relative_refused(explicit: GG, repo: Path, tmp_path: Path,
                                         monkeypatch) -> None:
    """Deliberate divergence, fail closed: git reads a relative GIT_COMMON_DIR
    against the cwd during discovery and against the root once it has
    chdir'ed there — `../other` from `a/b` finds no repository at all,
    `../../other` finds it but reads an empty config. gitguard refuses the
    relative form instead of choosing one of the two."""
    _other_gitdir(repo, tmp_path)
    sub = repo / "a/b"
    sub.mkdir(parents=True)
    for rel in ("../other", "../../other", "", "."):
        monkeypatch.setenv("GIT_COMMON_DIR", rel)
        with pytest.raises(gg_mod.Refuse, match="GIT_COMMON_DIR"):
            gg_mod.open_repo(gg_mod.find_root(sub) or repo)
        explicit.env["GIT_COMMON_DIR"] = rel
        r = explicit.run("git", "status", cwd=sub)
        assert r.blocked and "GIT_COMMON_DIR" in r.err, (rel, r.text)


@pytest.mark.discovery
def test_env_common_dir_discovery_head_only(gg: GG, repo: Path, tmp_path: Path,
                                            monkeypatch) -> None:
    """With GIT_COMMON_DIR, is_git_directory looks for objects/ and refs/ in
    the common dir: a directory holding a bare HEAD file is a gitdir for
    git's discovery (without `safe.bareRepository=explicit`, which makes git
    refuse it on its own). gitguard walked past it to the parent's .git."""
    other = _other_gitdir(repo, tmp_path)
    src = repo / "src"
    src.mkdir()
    (src / "HEAD").write_text("ref: refs/heads/main\n")
    assert _git_view(gg, src) == (repo.resolve(), (repo / ".git").resolve())   # no env: .git
    gg.env["GIT_COMMON_DIR"] = str(other)
    monkeypatch.setenv("GIT_COMMON_DIR", str(other))
    r = gg.git("rev-parse", "--absolute-git-dir", cwd=src)
    assert r.rc == 0 and Path(r.out.strip()).resolve() == src.resolve(), r.text   # oracle
    with pytest.raises(gg_mod.Refuse, match="bare gitdir"):
        gg_mod.find_root(src)
    r = gg.run("git", "status", cwd=src)
    assert r.blocked and "bare gitdir" in r.err, r.text


@pytest.mark.parametrize("form", ["absolute", "root_relative", "subdir_relative"])
def test_env_index_file_gitlinks_match_ls_files(gg: GG, repo: Path, form: str) -> None:
    """GIT_INDEX_FILE: the gitlinks git honours are those of that file. A
    relative value is read against the work tree root git chdirs to, from
    a subdirectory as well (`git rev-parse --git-path index` says so)."""
    sha = gg.git("rev-parse", "HEAD", cwd=repo).out.strip()
    (repo / "a/b").mkdir(parents=True)
    cwd = repo / "a/b" if form == "subdir_relative" else repo
    value = {"absolute": str(repo / "forged.idx"), "root_relative": "forged.idx",
             "subdir_relative": "a/forged.idx"}[form]
    gg.env["GIT_INDEX_FILE"] = value
    r = gg.git("update-index", "--add", "--cacheinfo", f"160000,{sha},vendor", cwd=cwd)
    assert r.rc == 0, r.text
    expect = {"absolute": repo / "forged.idx", "root_relative": repo / "forged.idx",
              "subdir_relative": repo / "a/forged.idx"}[form]
    assert expect.is_file()                                        # git wrote it there
    assert _git_gitlinks(gg, repo) == ["vendor"]                   # oracle
    assert index_gitlinks(repo / ".git/index") == []               # the gitdir's own: none
    os.environ["GIT_INDEX_FILE"] = value
    try:
        rp = gg_mod.open_repo(gg_mod.find_root(cwd))
        assert rp.index.resolve() == expect.resolve()
        assert index_gitlinks(rp.index) == ["vendor"]
    finally:
        del os.environ["GIT_INDEX_FILE"]


# ============ 9. index entry names git writes without validating them [55]
from tests.attacks._helpers import INDEX_ESCAPES, add_submodule, forge_index  # noqa: E402

CHECKOUT_FROM_INDEX = [["checkout", "--", "."], ["restore", "--worktree", "--", "."],
                       ["checkout-index", "-a", "-f"]]


def _case_insensitive(p: Path) -> bool:
    return (p / ".GIT").exists()


@pytest.mark.parametrize("cmd", CHECKOUT_FROM_INDEX, ids=lambda c: c[0])
@pytest.mark.parametrize("variant", sorted(INDEX_ESCAPES))
def test_forged_index_name_is_written_by_git(gg: GG, repo: Path, variant: str, cmd) -> None:
    """Oracle for the [55] attacks: git does write these names from a forged
    index (while it refuses them from a tree, see below). If a git version
    starts validating them, this test fails and [55] can be closed by git."""
    name, lands = INDEX_ESCAPES[variant]
    if variant == "dotgit_case" and not _case_insensitive(repo):
        pytest.skip("`.GIT` is another directory on a case-sensitive filesystem")
    target = (repo / lands).resolve()
    forge_index(gg, repo, [(0o100644, b"MARKER\n", name)])
    assert not target.exists()
    gg.git(*cmd, cwd=repo)
    assert target.is_file() and target.read_bytes() == b"MARKER\n", f"{variant}: not written"


@pytest.mark.parametrize("cmd", CHECKOUT_FROM_INDEX, ids=lambda c: c[0])
def test_forged_index_absolute_name_is_written_by_git(gg: GG, repo: Path, tmp_path: Path,
                                                      cmd) -> None:
    """Oracle for attack_index_absolute_name: an absolute name is written at
    that very path, anywhere on the disk. (Through a symlinked component —
    macOS `/var` → `/private/var` — git tries to unlink it instead.)"""
    target = tmp_path.resolve() / "abs-escaped"
    forge_index(gg, repo, [(0o100644, b"MARKER\n", str(target).encode())])
    gg.git(*cmd, cwd=repo)
    assert target.read_bytes() == b"MARKER\n"


def test_forged_tree_name_is_refused_by_git(gg: GG, repo: Path) -> None:
    """Control: the same name in a commit's tree is refused by git
    (verify_path) for every checkout, `restore --source` included — the
    vector is the index, not the objects."""
    blob = subprocess.run(["git", "hash-object", "-w", "--stdin"], cwd=repo, env=gg.env,
                          input=b"MARKER\n", capture_output=True, check=True).stdout.decode().strip()
    sub = blob
    for comp, mode in ((b"post-checkout", b"100644"), (b"hooks", b"40000")):
        raw = mode + b" " + comp + b"\0" + bytes.fromhex(sub)
        sub = subprocess.run(["git", "hash-object", "-t", "tree", "-w", "--literally", "--stdin"],
                             cwd=repo, env=gg.env, input=raw, capture_output=True,
                             check=True).stdout.decode().strip()
    f = gg.git("rev-parse", "HEAD:f", cwd=repo).out.strip()
    raw = b"40000 .git\0" + bytes.fromhex(sub) + b"100644 f\0" + bytes.fromhex(f)
    tree = subprocess.run(["git", "hash-object", "-t", "tree", "-w", "--literally", "--stdin"],
                          cwd=repo, env=gg.env, input=raw, capture_output=True,
                          check=True).stdout.decode().strip()
    c = gg.git("commit-tree", tree, "-p", "HEAD", "-m", "x", cwd=repo).out.strip()
    for cmd in (["restore", f"--source={c}", "--worktree", "--", "."], ["checkout", c, "--", "."],
                ["checkout", c], ["reset", "--hard", c], ["read-tree", "-u", "-m", c]):
        gg.git(*cmd, cwd=repo)
        assert not (repo / ".git/hooks/post-checkout").exists(), cmd


def test_forged_submodule_index_writes_into_superproject(gg: GG, repo: Path,
                                                         tmp_path: Path) -> None:
    """Oracle for attack_index_submodule_escape: `checkout -- .` in a
    submodule (what `submodule foreach`, an unwrapped git, runs) writes a
    `../.git/hooks/…` name of its index into the superproject's hooks."""
    sub = add_submodule(gg, repo, tmp_path)
    forge_index(gg, sub, [(0o100644, b"MARKER\n", b"../.git/hooks/post-checkout")],
                gitdir=repo / ".git/modules/sub")
    gg.git("checkout", "--", ".", cwd=sub)
    assert (repo / ".git/hooks/post-checkout").read_bytes() == b"MARKER\n"


@pytest.mark.parametrize("cmd", CHECKOUT_FROM_INDEX[:2], ids=lambda c: c[0])
def test_forged_index_hook_runs_through_wrapper(gg: GG, repo: Path, tmp_path: Path, cmd) -> None:
    """End to end: one write into `.git/index` (volatile, outside the
    fingerprint), then the user's wrapped `checkout -- .` wrote the hook and
    ran it in the same command. gitguard refuses before git starts, and the
    way out it names (`rm` the index, `git reset`) brings the repository back."""
    mark = tmp_path / "PWNED"
    forge_index(gg, repo, [(0o100755, f"#!/bin/sh\ntouch {mark}\n".encode(),
                            b".git/hooks/post-checkout")])
    r = gg.run("git", *cmd, cwd=repo)
    assert not mark.exists(), "the forged hook ran"
    assert r.blocked and not (repo / ".git/hooks/post-checkout").exists(), r.text
    assert "forged git index" in r.err and "git reset -q" in r.err, r.err
    (repo / ".git/index").unlink()
    assert not gg.run("git", "reset", "-q", cwd=repo).blocked
    assert not gg.run("git", *cmd, cwd=repo).blocked
    assert not mark.exists() and gg.git("status", "--porcelain", cwd=repo).out == ""


# verify_path as git applies it (`update-index --cacheinfo` calls it), with
# both protections on — the names a legitimate index can never hold. [55]
VERIFY_PATH_NAMES = [
    b"f", b"d/f", b".git", b".GIT", b".Git/x", b"x/.git", b"x/.git/y", b".git/hooks/a",
    b"./x", b"x/./y", b"x/.", b"../x", b"x/../y", b"x/..", b"..", b".", b"x//y", b"//x",
    b"/x", b"x/", b".gitx", b".git~", b".git-x", b"git~1", b"GIT~1/x", b"git~2", b"x/git~1",
    b".git ", b".git.", b".git. .", b".git :x", b".git:x", b".git\\x", b"x\\.git", b"x\\.git\\y",
    b"\\.git", b"x\\git~1", b".g\xe2\x80\x8cit", b"\xe2\x80\x8c.git", b".git\xe2\x80\x8c",
    b".\xef\xbb\xbfgit/x", b".gi\xe2\x80\x8et/x", b".git\xff", b".gi\xff", b"\xff.git",
    b".gitmodules", b".gitmodules ", b".gitmodules.", b".gitmodules:x", b"x/.gitmodules",
    b".GITMODULES", b"gitmod~1", b"GITMOD~4", b"gitmod~5", b"gi7eba~1", b"gi7eba~9",
    b"gi7eb~12", b".gitmodules/x", b".g\xe2\x80\x8citmodules", b"x\\.gitmodules",
    b"..x", b"...", b"x..", b"x.", b".github/x", b".gitignore", b"a.git/x", b"x.git",
    b".g/x", b"\xc3\xa9/.git", b" .git", b"x/ .git", b".git/", b"x/.git/",
    b".git /x", b".git./x", b"git~1/x", b"git~1 /x", b"x\\.git /y", b"x\\git~1\\y",
    b".git::$INDEX_ALLOCATION", b"git~1:x", b".gitmodules /x", b"gitmod~1:x",
]


@pytest.mark.parametrize("mode", [0o100644, 0o120000], ids=["file", "symlink"])
def test_verify_path_matches_git(gg: GG, tmp_path: Path, mode: int) -> None:
    """Every name: gitguard refuses exactly what git's verify_path refuses
    (a name git refuses but gitguard accepts is a [55] bypass; the reverse,
    a false positive)."""
    blob = "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"
    o = tmp_path / "o"
    assert gg.git("init", "-q", str(o)).rc == 0
    diffs = []
    for i, name in enumerate(VERIFY_PATH_NAMES):
        env = dict(gg.env, GIT_INDEX_FILE=str(tmp_path / f"idx{i}"))
        r = subprocess.run([b"git", b"-c", b"core.protectHFS=true", b"-c", b"core.protectNTFS=true",
                            b"update-index", b"--add", b"--cacheinfo",
                            b"%o,%s,%s" % (mode, blob.encode(), name)],
                           cwd=o, env=env, capture_output=True)
        git_ok = r.returncode == 0
        assert git_ok or b"nvalid path" in r.stderr, (name, r.stderr)   # the oracle is verify_path
        if git_ok != gg_mod.verify_path(name, mode):
            diffs.append((name, "git accepts" if git_ok else "git refuses", r.stderr[:80]))
    assert not diffs, diffs


# ================== local remotes: the hooks git runs on push are watched [61]
def _remote_layout(gg: GG, tmp_path: Path, layout: str) -> str:
    """Build a remote in the volume; return the URL to configure."""
    v = tmp_path / "vol"
    v.mkdir()
    init = lambda *a: gg.git("init", "-q", *map(str, a))
    if layout == "bare":
        init("--bare", v / "r.git"); return str(v / "r.git")
    if layout == "bare_suffix_tried":
        init("--bare", v / "r.git"); return str(v / "r")
    if layout == "bare_trailing_slash":
        init("--bare", v / "r.git"); return str(v / "r.git") + "/"
    if layout == "file_url":
        init("--bare", v / "r.git"); return "file://" + str(v / "r.git")
    if layout == "file_url_encoded_space":                     # [69]
        init("--bare", v / "My Repos/r.git"); return "file://" + str(v / "My%20Repos/r.git")
    if layout == "file_url_encoded_lowercase_dot":
        init("--bare", v / "r.git"); return "file://" + str(v / "r%2egit")
    if layout == "file_url_encoded_slash":
        init("--bare", v / "d/r.git"); return "file://" + str(v / "d%2Fr.git")
    if layout == "file_url_invalid_escape_kept":
        init("--bare", v / "a%zz/r.git"); return "file://" + str(v / "a%zz/r.git")
    if layout == "file_url_double_encoding_decoded_once":
        init("--bare", v / "a%20b/r.git"); return "file://" + str(v / "a%2520b/r.git")
    if layout == "file_url_host_dropped":                      # parse_connect_url: path from the first `/`
        init("--bare", v / "r.git"); return "file://host.example" + str(v / "r.git")
    if layout == "file_url_bracket_host":                      # host_end: a `/` inside `[…]` is not the path
        init("--bare", v / "r.git"); return "file://u@[::1/x]" + str(v / "r.git")
    if layout == "file_url_encoded_colon_slashes":             # `a%3A%2F%2F` is the directory `a:`
        init("--bare", v / "a:/r.git"); return "file://" + str(v) + "/a%3A%2F%2Fr.git"
    if layout == "worktree_repo":
        init(v / "o"); return str(v / "o")
    if layout == "dotgit_dotgit":
        init(v / "o.git"); return str(v / "o")
    if layout == "gitfile":
        init("--separate-git-dir", v / "gd", v / "o"); return str(v / "o")
    if layout == "commondir_relative":
        init("--bare", v / "main.git")
        init("--bare", v / "r.git")
        (v / "r.git/commondir").write_text("../main.git\n"); return str(v / "r.git")
    if layout == "linked_worktree":
        init(v / "m")
        (v / "m/f").write_text("f\n")
        gg.git("add", "f", cwd=v / "m")
        gg.git("commit", "-qm", "f", cwd=v / "m")
        assert gg.git("worktree", "add", "-q", str(v / "w"), cwd=v / "m").rc == 0
        return str(v / "w")
    raise AssertionError(layout)


REMOTE_LAYOUTS = ["bare", "bare_suffix_tried", "bare_trailing_slash", "file_url",
                  "file_url_encoded_space", "file_url_encoded_lowercase_dot",
                  "file_url_encoded_slash", "file_url_invalid_escape_kept",
                  "file_url_double_encoding_decoded_once", "file_url_host_dropped",
                  "file_url_bracket_host", "file_url_encoded_colon_slashes",
                  "worktree_repo", "dotgit_dotgit", "gitfile",
                  "commondir_relative", "linked_worktree"]


@pytest.mark.parametrize("layout", REMOTE_LAYOUTS)
def test_local_remote_hooks_git_runs_are_watched(gg: GG, repo: Path, tmp_path: Path,
                                                 layout: str) -> None:
    url = _remote_layout(gg, tmp_path, layout)
    log = tmp_path / "ran.log"
    hooks = [p for p in (tmp_path / "vol").rglob("hooks") if p.is_dir()]
    for h in hooks:
        write_exec(h / "pre-receive", f"#!/bin/sh\necho {h} >> '{log}'\n")
    gg.git("remote", "add", "origin", url, cwd=repo)
    r = gg.git("push", "-q", "origin", "HEAD:refs/heads/probe", cwd=repo)
    assert r.rc == 0 and log.exists(), f"oracle: git ran no pre-receive\n{r.text}"
    ran = Path(log.read_text().split("\n")[0])
    gg.trust(repo)
    write_exec(ran / "pre-receive", EVIL)
    res = gg.check(repo)
    assert res.blocked, f"{ran}/pre-receive (run by git push) rewritten, accepted\n{res.text}"


@pytest.mark.parametrize("layout", REMOTE_LAYOUTS)
def test_local_remote_relative_hookspath_where_git_resolves_it(gg: GG, repo: Path, tmp_path: Path,
                                                               layout: str) -> None:
    """[67] a relative core.hooksPath in the remote's config: a pre-receive
    is planted under `rel-hooks/` in every gitdir and work tree of the
    volume, git says which one it runs, rewriting that one is seen."""
    url = _remote_layout(gg, tmp_path, layout)
    vol = tmp_path / "vol"
    for c in vol.rglob("config"):
        if (c.parent / "HEAD").is_file():
            with open(c, "a") as fh:
                fh.write("[core]\n\thooksPath = rel-hooks\n")
    log = tmp_path / "ran.log"
    gitdirs = {h.parent for h in vol.rglob("HEAD")
               if (h.parent / "objects").is_dir() or (h.parent / "commondir").is_file()}
    for d in gitdirs | {g.parent for g in gitdirs}:
        h = d / "rel-hooks"
        write_exec(h / "pre-receive", f"#!/bin/sh\necho {h} >> '{log}'\n")
    gg.git("remote", "add", "origin", url, cwd=repo)
    r = gg.git("push", "-q", "origin", "HEAD:refs/heads/probe", cwd=repo)
    assert r.rc == 0 and log.exists(), f"oracle: git ran no pre-receive\n{r.text}"
    ran = Path(log.read_text().split("\n")[0])
    gg.trust(repo)
    write_exec(ran / "pre-receive", EVIL)
    res = gg.check(repo)
    assert res.blocked, f"{ran}/pre-receive (run by git push) rewritten, accepted\n{res.text}"
