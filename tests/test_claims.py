"""gitguard's lists of claims about git, held to git itself.

Each closed list in gitguard.py says "git never does X here": a global flag
that does not move the gitdir (GLOBAL_FLAGS), a command that never enters a
gitlink the index does not hold (SWITCH_EXEMPT), the options of clone and
init (NEW_REPO_OPTIONS), the index extensions git requires
(KNOWN_REQUIRED_EXTENSIONS). Every one of them fell in a review because
nothing checked the claim itself, only the attacks known at the time: [97]
(`--bare` taken for inert), [86] (`commit` exempt), [98] (`--templ=`). Here
each entry is checked against the git under test, so that a wrong entry or
a git upgrade that changes the answer fails here first (run after a git
upgrade, with `pytest -m discovery`).
"""
from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import pytest

import gitguard as gg_mod
from tests.conftest import GG, REAL_GIT
from tests.test_commands import EDITOR, _gitlink_in_head, _typechange_to_repo


def _help(*args: str) -> str:
    r = subprocess.run([REAL_GIT, *args], capture_output=True, text=True,
                       env={**os.environ, "LC_ALL": "C"})
    return r.stdout + r.stderr


# ============================================== GLOBAL_FLAGS vs git's gitdir
def _git_gitdir(gg: GG, args: list[str], cwd: Path) -> Path | None:
    """The gitdir git uses for `git <args> rev-parse --absolute-git-dir`,
    None when it uses none (or prints something else and exits, as
    `--exec-path` does)."""
    r = gg.git(*args, "rev-parse", "--absolute-git-dir", cwd=cwd)
    out = r.out.strip()
    if r.rc or not out or not gg_mod.is_bare_gitdir(Path(out)):
        return None
    return Path(out).resolve()


def _gg_gitdir(args: list[str], cwd: Path, monkeypatch) -> Path | str | None:
    """The gitdir gitguard checks for the same command line, "refused" when
    it refuses, None when it sees no repository."""
    monkeypatch.delenv("GIT_DIR", raising=False)
    monkeypatch.delenv("GIT_WORK_TREE", raising=False)
    try:
        o = gg_mod.split_global_options([*args, "rev-parse"], cwd)
        if o.gitdir is not None:
            monkeypatch.setenv("GIT_DIR", str(o.gitdir.resolve()))
        monkeypatch.chdir(o.cwd)
        root = gg_mod.find_root(Path.cwd())
        if root is None:
            return None
        return gg_mod.open_repo(root).gitdir.resolve()
    except gg_mod.Refuse:
        return "refused"


def _plant_gitdir_at_root(repo: Path) -> None:
    """A gitdir layout in the tree's root, next to `.git`: a flag that makes
    git take the cwd as its gitdir shows here."""
    (repo / "HEAD").write_text("ref: refs/heads/main\n")
    (repo / "objects").mkdir()
    (repo / "refs").mkdir()


@pytest.mark.discovery
@pytest.mark.parametrize("flag", sorted(gg_mod.GLOBAL_FLAGS) + ["--bare"])
def test_global_flag_gitdir_as_git(gg: GG, repo: Path, monkeypatch, flag: str) -> None:
    """[97] for every global flag gitguard lets through, the gitdir git
    opens is the one gitguard checks (or gitguard refuses)."""
    _plant_gitdir_at_root(repo)
    want = _git_gitdir(gg, [flag], repo)
    got = _gg_gitdir([flag], repo, monkeypatch)
    if want is not None:
        assert got in (want, "refused"), (flag, want, got)


def test_git_usage_global_options_are_known() -> None:
    """Every global option git's usage names is one gitguard interprets (an
    unknown one is refused: fail closed, but a known one misread is a
    bypass, so each must be in a table the test above checks)."""
    usage = _help()
    opts = set(re.findall(r"(?<![\w-])(--?[a-zA-Z][\w-]*)", usage.split("<command>")[0]))
    opts -= {"--version", "-v", "-h", "--help"}            # GLOBAL_STOP
    known = (gg_mod.GLOBAL_FLAGS | gg_mod.GLOBAL_WITH_ARG | gg_mod.GLOBAL_STOP | {"--bare"}
             | {o.rstrip("=") for o in gg_mod.GLOBAL_WITH_EQ})
    assert opts and opts <= known, sorted(opts - known)


# =================================== SWITCH_EXEMPT vs a gitlink from a tree
# Every form of each exempt command, run by the real git *without* the
# switch, after each planting of [86]: none may enter the planted
# repository. A form that does is a wrong exemption, i.e. a bypass.
EXEMPT_FORMS = {
    "status": [["status"], ["status", "--short"], ["status", "--porcelain=v2"],
               ["status", "-uall"]],
    "diff": [["diff"], ["diff", "HEAD"], ["diff", "--cached"], ["diff", "--stat"],
             ["diff", "HEAD~1", "HEAD"], ["diff", "--submodule=log", "HEAD~1"]],
    "config": [["config", "--list"], ["config", "--get", "core.bare"]],
    "var": [["var", "-l"]],
}


def test_exempt_forms_cover_switch_exempt() -> None:
    assert set(EXEMPT_FORMS) == set(gg_mod.SWITCH_EXEMPT)


@pytest.mark.parametrize("planting", ["typechange", "gitlink_in_head"])
@pytest.mark.parametrize("cmd", sorted(gg_mod.SWITCH_EXEMPT))
def test_exempt_command_never_enters_a_gitlink_from_a_tree(gg: GG, repo: Path, tmp_path: Path,
                                                           cmd: str, planting: str) -> None:
    """[86] SWITCH_EXEMPT says these commands never put a gitlink in an
    index then report on it: checked with the real git, no switch, every
    form, both ways the sandbox brings a gitlink (a tracked file replaced
    by a repository, a HEAD moved to a commit with a gitlink)."""
    mark = tmp_path / "RAN"
    if planting == "typechange":
        _typechange_to_repo(gg, repo, mark)
        r = repo
    else:
        r = _gitlink_in_head(gg, tmp_path, mark)
    gg.env["GIT_EDITOR"] = EDITOR
    for form in EXEMPT_FORMS[cmd]:
        gg.git(*form, cwd=r)
        assert not mark.exists(), f"`git {' '.join(form)}` entered the planted repository"


def test_exempt_control_a_non_exempt_command_enters(gg: GG, repo: Path, tmp_path: Path) -> None:
    """Positive control of the plantings above: `commit -a` (no longer
    exempt, [86]) does enter the typechanged repository without the switch."""
    mark = tmp_path / "RAN"
    _typechange_to_repo(gg, repo, mark)
    gg.env["GIT_EDITOR"] = EDITOR
    gg.git("commit", "-a", cwd=repo)
    assert mark.exists()


# ============================================ NEW_REPO_OPTIONS vs `git -h`
def _options_from_help(text: str) -> tuple[dict[str, bool], set[str]]:
    """({long option: takes a separate value}, short letters taking one)
    from parse-options' help: `-b, --[no-]branch <branch>`, `--[no-]bare`,
    `--shared[=<permissions>]` (an attached value only), `-n, --no-checkout`."""
    longs: dict[str, bool] = {}
    shorts: set[str] = set()
    for line in text.splitlines():
        m = re.match(r"\s+(?:-(\w), )?--(?:\[no-\])?([a-z][\w-]*)( <|\[=)?", line)
        if not m:
            continue
        short, name, arg = m.groups()
        takes = arg == " <"
        longs["--" + name] = takes
        if short and takes:
            shorts.add(short)
    return longs, shorts


# Options of the tables that an older git lacks (`git clone -h` has no
# `--revision` before 2.49): the table may hold them, this git need not.
NEWER_OPTIONS = {"clone": {"--revision"}, "init": set()}


@pytest.mark.discovery
@pytest.mark.parametrize("cmd", ["clone", "init"])
def test_new_repo_options_match_git(cmd: str) -> None:
    """[98] NEW_REPO_OPTIONS is git's own list: every option of this git is
    in the table with the same arity (a new option of a future git fails
    here; its prefixes would otherwise be misread), and the table holds
    nothing this git lacks but NEWER_OPTIONS. A `--no-x` the help lists on
    its own (`--no-tags`, git ≤ 2.48) is the negation of the table's `--x`,
    which is how _long_option reads it."""
    want_long, want_short = _options_from_help(_help(cmd, "-h"))
    longs, shorts = gg_mod.NEW_REPO_OPTIONS[cmd]
    for name in list(want_long):
        base = "--" + name[5:]
        if name.startswith("--no-") and name not in longs and base in longs:
            assert gg_mod._long_option(name, longs) == (base, True)
            want_long[base] = want_long.pop(name)
    for name, takes in want_long.items():
        assert name in longs, name
        assert longs[name] == takes, name
    assert set(longs) - set(want_long) <= NEWER_OPTIONS[cmd], sorted(set(longs) - set(want_long))
    assert set(shorts) == want_short


@pytest.mark.parametrize("cmd", ["clone", "init"])
def test_every_unique_prefix_is_its_option(cmd: str) -> None:
    """[98] parse-options: a unique prefix of a long option is that option,
    an ambiguous one is none; `--no-<prefix>` its negation."""
    longs = gg_mod.NEW_REPO_OPTIONS[cmd][0]
    for opt in longs:
        for n in range(3, len(opt) + 1):
            pre = opt[:n]
            hits = [o for o in longs if o.startswith(pre)]
            got = gg_mod._long_option(pre, longs)
            if pre in longs or len(hits) == 1:
                assert got == ((pre if pre in longs else opt), False), pre
            else:
                assert got[0] is None or got[0] == pre, (pre, got)


def test_abbreviated_template_is_honoured_by_git(gg: GG, tmp_path: Path) -> None:
    """[98] the oracle for the prefix rule: git copies the template's hooks
    with `--te=` (shortest unique prefix for init)."""
    tpl = tmp_path / "tpl"
    (tpl / "hooks").mkdir(parents=True)
    (tpl / "hooks/pre-commit").write_text("#!/bin/sh\n")
    assert gg.git("init", "-q", f"--te={tpl}", str(tmp_path / "n")).rc == 0
    assert (tmp_path / "n/.git/hooks/pre-commit").exists()
    assert gg_mod._long_option("--te", gg_mod.NEW_REPO_OPTIONS["init"][0])[0] == "--template"


# =========================== index extensions git writes vs the parser's rule
INDEX_FEATURES = {
    "plain": [],
    "untracked_cache": ["-c", "core.untrackedCache=true"],
    "v4": ["-c", "index.version=4"],
    "skipHash": ["-c", "index.skipHash=true"],
    "manyFiles": ["-c", "feature.manyFiles=true"],
}


@pytest.mark.parametrize("feature", list(INDEX_FEATURES))
def test_indexes_git_writes_are_read(gg: GG, repo: Path, feature: str) -> None:
    """[87] KNOWN_REQUIRED_EXTENSIONS: no index git writes in an ordinary
    configuration carries a required extension the parser refuses."""
    pre = INDEX_FEATURES[feature]
    (repo / "u").write_text("u\n")
    assert gg.git(*pre, "update-index", "--add", "u", cwd=repo).rc == 0
    assert gg.git(*pre, "status", "-uall", cwd=repo).rc == 0     # writes UNTR, TREE…
    assert gg_mod.index_entries(repo / ".git/index") == ([], [])


def test_sparse_index_is_read_split_index_refused(gg: GG, repo: Path) -> None:
    """[87] [31] the two required extensions git writes: `sdir` is read
    (its directories returned), `link` refused (a split index)."""
    (repo / "src").mkdir()
    (repo / "vendor").mkdir()
    (repo / "src/a").write_text("a\n")
    (repo / "vendor/b").write_text("b\n")
    gg.git("add", ".", cwd=repo)
    gg.git("commit", "-qm", "dirs", cwd=repo)
    assert gg.git("sparse-checkout", "set", "--cone", "--sparse-index", "src", cwd=repo).rc == 0
    assert b"sdir" in (repo / ".git/index").read_bytes()
    assert gg_mod.index_entries(repo / ".git/index") == ([], ["vendor/"])
    assert gg.git("sparse-checkout", "disable", cwd=repo).rc == 0
    assert gg.git("update-index", "--split-index", cwd=repo).rc == 0
    with pytest.raises(gg_mod.Refuse, match="splitIndex"):
        gg_mod.index_entries(repo / ".git/index")
