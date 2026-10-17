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
from gitguard import _expand2, global_config_files, index_gitlinks, parse_git_config
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
]

PARSER_DIVERGENT = [
    # Security: git sees core.hookspath, gitguard does not (see also E2E below).
    ("utf8_bom", b"\xef\xbb\xbf[core]\n\thooksPath = .githooks\n",
     "UTF-8 BOM: git ignores it, gitguard reads `\\ufeff[core]` as a key → empty section"),
    ("comment_line_backslash_hash", b"[core]\n# note \\\n\thooksPath = .githooks\n",
     "trailing `\\` on a comment line: git does not continue, gitguard swallows the next line"),
    ("comment_line_backslash_semi", b"[core]\n; note \\\n\thooksPath = .githooks\n",
     "same with `;`"),
    ("inline_comment_backslash_hash", b"[core]\n\tpager = less # x \\\n\thooksPath = .githooks\n",
     "trailing `\\` inside an end-of-value comment: not a continuation for git"),
    ("inline_comment_backslash_semi", b"[core]\n\tpager = less ; x \\\n\thooksPath = .githooks\n",
     "same with `;`"),
    ("backslash_at_eof", b"[core]\n\thooksPath = .githooks\\",
     "trailing `\\` without a newline: git ignores it, gitguard keeps `.githooks\\`"),
    ("nul_in_value", b"[core]\n\thooksPath = .githooks\x00junk\n",
     "git truncates the value at the NUL (`.githooks`), gitguard keeps `.githooks\\0junk`"),
    ("internal_whitespace", b"[core]\n\thooksPath = my  \thooks\n",
     "git 2.50 keeps unquoted internal whitespace as is (`my  \\thooks`), "
     "_unquote collapses it to one space → `hooksPath = my  hooks` targets another directory; "
     "test_unit.test_parse_escapes_and_continuation also expects the collapse"),
    # Fidelity (no known vector):
    ("subsection_unknown_escape", b'[a "b\\\\c\\"d\\e"]\n\tk = v\n',
     "subsection: git strips the `\\` before any character, gitguard only before \\ and \""),
    ("vertical_tab_value", b"[core]\n\thooksPath =\x0b.githooks\n",
     "git's isspace = \"\\t\\n\\r\"; str.strip() also strips \\v\\f"),
    ("nbsp_trailing", "[core]\n\thooksPath = .githooks\u00a0\n".encode(),
     "str.strip() strips the no-break space, git keeps it in the value"),
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


@pytest.mark.parametrize("data", [
    pytest.param(c[1], marks=XF(strict=True, reason=c[2]), id=c[0]) for c in PARSER_DIVERGENT])
def test_parser_divergence(tmp_path: Path, data: bytes) -> None:
    _assert_parser_covers_git(tmp_path, data)


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


@pytest.mark.parametrize("edit", [
    pytest.param(c[1], marks=XF(strict=True, reason="parser divergence (section 1)"), id=c[0])
    for c in E2E_PARSER])
def test_hookspath_e2e_divergence(gg: GG, repo: Path, edit) -> None:
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
    pytest.param(f"~{getpass.getuser()}/x", marks=XF(strict=True, reason=(
        "`~user/`: git expands it (getpwnam), _expand2 does not → `core.hooksPath = ~jb/vol/hooks` "
        "or `include.path = ~jb/vol/x.cfg` never watched")), id="tilde_user"),
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
SHELL_OK = ["./tool.sh", "sh tool.sh", "sh -c ./tool.sh", '"./tool.sh"']
SHELL_DIVERGENT = [
    ("and_and", "./tool.sh&&true"),
    ("pipe", "./tool.sh|cat"),
    ("redirect", "sh<tool.sh"),
    ("subshell", "(./tool.sh)"),
    ("cmd_subst", "echo $(./tool.sh)"),
    ("function", "f() { ./tool.sh; }; f"),        # very common alias form
    ("semicolon", "./tool.sh;true"),
]


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


@pytest.mark.parametrize("cmd", SHELL_OK)
def test_alias_script_watched(gg: GG, repo: Path, cmd: str) -> None:
    _alias_e2e(gg, repo, cmd)


@pytest.mark.parametrize("cmd", [
    pytest.param(c, id=n, marks=XF(strict=True, reason=(
        "_value_tokens does not split on sh operators (&& | < ( ) $( ; {)")))
    for n, c in SHELL_DIVERGENT])
def test_alias_script_shell_operators(gg: GG, repo: Path, cmd: str) -> None:
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


def test_discovery_subdir(explicit: GG, repo: Path, monkeypatch) -> None:
    (repo / "a/b").mkdir(parents=True)
    _assert_same_repo(explicit, repo / "a/b", monkeypatch)


def test_discovery_linked_worktree(explicit: GG, repo: Path, tmp_path: Path, monkeypatch) -> None:
    assert explicit.git("worktree", "add", "-q", str(tmp_path / "wt"), cwd=repo).rc == 0
    _assert_same_repo(explicit, tmp_path / "wt", monkeypatch)


@XF(strict=True, reason=(
    "`.git` directory invalid for git (no HEAD/objects/refs): git ignores it and walks up "
    "to the parent; gitguard stops on it and checks (then may trust) another gitdir"))
def test_discovery_invalid_dotgit_dir_skipped_by_git(explicit: GG, repo: Path, monkeypatch) -> None:
    (repo / "src/.git").mkdir(parents=True)
    (repo / "src/.git/config").write_text("[core]\n")
    _assert_same_repo(explicit, repo / "src", monkeypatch)


@pytest.mark.parametrize("layout", ["commondir", "head_symlink_unborn", "full_bare"])
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


@XF(strict=True, reason=(
    "core.worktree in .git/config: git takes that directory as the root (and resolves a "
    "relative core.hooksPath there), gitguard keeps the directory containing .git"))
def test_core_worktree_hookspath(explicit: GG, repo: Path, tmp_path: Path) -> None:
    other = tmp_path / "other"
    write_exec(other / ".githooks/pre-commit", BENIGN)
    explicit.git("config", "core.worktree", str(other), cwd=repo)
    explicit.git("config", "core.hooksPath", ".githooks", cwd=repo)
    assert explicit.git("rev-parse", "--show-toplevel", cwd=repo).out.strip() == str(other.resolve())
    explicit.run("trust", cwd=repo)
    write_exec(other / ".githooks/pre-commit", EVIL)
    assert explicit.check(repo).blocked


# ========================================= 6. index gitlinks vs ls-files -s
def _git_gitlinks(gg: GG, repo: Path) -> list[str]:
    r = subprocess.run(["git", "ls-files", "-s", "-z"], cwd=repo, env=gg.env, capture_output=True)
    out = []
    for rec in r.stdout.split(b"\0"):
        if rec.startswith(b"160000 "):
            out.append(rec.split(b"\t", 1)[1].decode(errors="surrogateescape"))
    return sorted(out)


@pytest.mark.parametrize("skiphash", [False, True], ids=["hash", "skipHash"])
@pytest.mark.parametrize("version", [2, 3, 4])
def test_index_gitlinks_match_ls_files(gg: GG, repo: Path, version: int, skiphash: bool) -> None:
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
    assert sorted(index_gitlinks(repo / ".git")) == want


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


def test_default_system_config_is_real_gits(tmp_path: Path) -> None:
    """gitguard's /etc/gitconfig must be REAL_GIT's (Debian: /etc/gitconfig;
    Homebrew: /opt/homebrew/etc/gitconfig, different)."""
    real = gg_mod.REAL_GIT
    if not Path(real).exists():
        pytest.skip(f"{real} missing")
    env = {k: v for k, v in os.environ.items()
           if k not in ("GIT_CONFIG_SYSTEM", "GIT_CONFIG_NOSYSTEM")}
    env["GIT_EDITOR"] = "echo"
    r = subprocess.run([real, "config", "--system", "--edit"], cwd=tmp_path, env=env,
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert Path(r.stdout.strip()).resolve() == Path("/etc/gitconfig").resolve()


@XF(strict=True, reason=(
    "GIT_CONFIG_COUNT/KEY_n/VALUE_n (and GIT_CONFIG_PARAMETERS, `-c`): git honours them, "
    "config_refs does not read them → a hooksPath set by the environment is never watched"))
def test_env_config_hookspath(gg: GG, repo: Path) -> None:
    gg.env.update(GIT_CONFIG_COUNT="1", GIT_CONFIG_KEY_0="core.hooksPath",
                  GIT_CONFIG_VALUE_0=".githooks")
    write_exec(repo / ".githooks/pre-commit", BENIGN)
    assert gg.git("config", "--get", "core.hookspath", cwd=repo).out.strip() == ".githooks"
    gg.trust(repo)
    write_exec(repo / ".githooks/pre-commit", EVIL)
    assert gg.check(repo).blocked
