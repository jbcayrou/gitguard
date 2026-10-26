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


# ====================================== the inventory: git's own universe
# tests/inventory/git-<ver>.txt (tests/inventory.py, from git's source) names
# everything git opens under a gitdir, every config key it reads as a path,
# its hooks and its global options. The bypass catalogue grew one case at a
# time because that universe was never written down ([19] [51] [55] [83]
# [88] each a gitdir name, [56] a pathname key, [97] a global option). Here
# every item must be classified; an item git knows and gitguard does not
# fails first. On a git upgrade: regenerate, diff, classify the new lines.
INVENTORY = sorted((Path(__file__).parent / "inventory").glob("git-*.txt"))[-1]


def _inventory(section: str) -> list[str]:
    items, cur = [], None
    for line in INVENTORY.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("["):
            cur = line.strip("[]")
        elif cur == section:
            items.append(line)
    assert items, section
    return items


# Gitdir names git opens that gitguard hashes on purpose, or refuses: the
# classification that is neither "volatile" nor "read as instructions".
GITDIR_HASHED = {
    "config": "the trusted config itself",
    "config.worktree": "per-worktree config (extensions.worktreeConfig), parsed like config",
    "info/exclude": "ignore patterns: git reads, never rewrites; a change is the sandbox's",
    "info/attributes": "filters and drivers are defined here: the pivot [13]",
    "objects/info/alternates": "object directories git reads: watched, [13]",
    "modules": "submodule gitdirs, walked as roots (_child_root)",
    "worktrees": "linked worktrees, walked as roots (_child_root)",
    "info/rev-cache": "no writer left in git: deny by default",
    "lost-found/%s/%s": "fsck --lost-found writes blob content through a planted symlink: kept watched [83]",
    "info/fast-import/%s": "fast-import crash reports: written once, never by an ordinary command",
    "fast_import_crash_%": "same",
    "next-index-%": "temporary index of a partial commit, renamed or unlinked by the command",
    "shallow_XXXXXX": "temporary, renamed over `shallow` (volatile) or unlinked",
    "sharedindex_XXXXXX": "temporary of the split index",
    "sharedindex.%s": "split index: refused (check_split_index) [31]",
    "fsmonitor--daemon.ipc": "the builtin fsmonitor's socket: not a regular file, _hash_file "
                             "skips it; a regular file put there is watched, git runs nothing from it",
}


def _volatile_at(rel: str) -> bool:
    parts = rel.split("/")
    return any(gg_mod._volatile_dir("/".join(parts[:i])) for i in range(1, len(parts))) \
        or gg_mod._volatile_dir(rel) or gg_mod._volatile_file(rel, False)


@pytest.mark.parametrize("name", _inventory("gitdir"))
def test_every_gitdir_name_git_opens_is_classified(name: str) -> None:
    """Every name under [gitdir] is volatile (VOLATILE_DIRS/VOLATILE_FILES,
    at its anchored position), read as instructions (VOLATILE_READERS), or
    hashed/refused on purpose (GITDIR_HASHED). An unclassified name is a
    future [19] (instructions in a volatile zone) or a future [100] (a
    false positive on an ordinary command)."""
    if name in gg_mod.VOLATILE_READERS:
        return
    if _volatile_at(name):
        return
    assert name in GITDIR_HASHED, f"{name}: git opens it under a gitdir, gitguard has no classification"


def test_every_reader_file_is_volatile() -> None:
    """A reader is for a file the fingerprint cannot hold: each one must
    sit in a volatile zone (otherwise the hash already covers it)."""
    for rel in gg_mod.VOLATILE_READERS:
        assert _volatile_at(rel), rel


# Pathname keys git runs rather than reads: the generic program rule covers
# them (any token that is an existing file is watched), not DATA_KEYS.
PATHNAME_PROGRAMS = {"core.fsmonitor": "a hook path git runs (the non-boolean form)"}


@pytest.mark.parametrize("key", _inventory("pathname"))
def test_every_pathname_key_is_classified(key: str) -> None:
    """Every key git reads through git_config_pathname is a directory git
    reads hooks from (DIR_KEYS), a file git reads as data (DATA_KEYS, never
    watched: the [56] trap) or a program (PATHNAME_PROGRAMS)."""
    section, _, k = key.rpartition(".")
    if (section, k) in gg_mod.DIR_KEYS or gg_mod._data_key(section, k):
        return
    assert key in PATHNAME_PROGRAMS, f"{key}: a pathname key gitguard has not classified"


@pytest.mark.parametrize("hook", _inventory("hooks"))
def test_every_hook_under_a_tree_hookspath_is_watched(gg: GG, repo: Path, hook: str) -> None:
    """[1] for every hook git documents: under a core.hooksPath in the tree,
    rewriting it is seen."""
    from tests.conftest import write_exec
    p = repo / ".githooks" / hook
    write_exec(p)
    assert gg.git("config", "core.hooksPath", ".githooks", cwd=repo).rc == 0
    gg.trust(repo)
    assert not gg.check(repo).blocked
    p.write_text("#!/bin/sh\ntouch RAN\n")
    assert gg.check(repo).blocked, hook


def test_inventory_global_options_are_known() -> None:
    """[97] every option git.c's handle_options compares `cmd` to is one
    gitguard interprets (the `git --help` oracle above sees only the usage
    text; the source names them all)."""
    opts = set(_inventory("options"))
    known = (gg_mod.GLOBAL_FLAGS | gg_mod.GLOBAL_WITH_ARG | gg_mod.GLOBAL_STOP | {"--bare"}
             | {o.rstrip("=") for o in gg_mod.GLOBAL_WITH_EQ})
    assert opts <= known, sorted(opts - known)


# Config keys whose value git runs: no single signature in git's source (the
# inventory has no [program] section), curated from Documentation/config.
# The rule in gitguard is generic — any token of any value that is an
# existing file is watched, no list — and this corpus proves it reaches each
# key's value syntax (`!` aliases, `%f` placeholders, a `-c` pair).
PROGRAM_KEYS = {
    "core.sshCommand": "{p}", "core.pager": "{p}", "core.editor": "{p}",
    "sequence.editor": "{p}", "core.askPass": "{p}", "core.fsmonitor": "{p}",
    "core.alternateRefsCommand": "{p}", "core.gitProxy": "{p}",
    "gpg.program": "{p}", "gpg.ssh.program": "{p}", "gpg.ssh.defaultKeyCommand": "{p}",
    "diff.external": "{p}", "diff.x.command": "{p}", "diff.x.textconv": "{p}",
    "merge.x.driver": "{p} %O %A %B", "filter.x.clean": "{p} %f",
    "filter.x.smudge": "{p} %f", "filter.x.process": "{p}",
    "credential.helper": "{p}", "alias.x": "!{p}", "hook.x.command": "{p}",
    "uploadpack.packObjectsHook": "{p}", "tar.tgz.command": "{p}",
    "remote.origin.uploadpack": "{p}", "remote.origin.receivepack": "{p}",
    "mergetool.x.cmd": "{p}", "difftool.x.cmd": "{p}", "interactive.diffFilter": "{p}",
    "sendemail.sendmailCmd": "{p}", "sendemail.smtpServer": "{p}",
    "browser.x.cmd": "{p}", "man.x.cmd": "{p}", "instaweb.browser": "{p}",
    "pager.log": "{p}", "maintenance.x.command": "{p}",
}


@pytest.mark.parametrize("key", sorted(PROGRAM_KEYS))
def test_program_key_naming_a_tree_script_is_watched(gg: GG, repo: Path, key: str) -> None:
    from tests.conftest import write_exec
    write_exec(repo / "t.sh")
    assert gg.git("config", key, PROGRAM_KEYS[key].format(p="./t.sh"), cwd=repo).rc == 0
    gg.trust(repo)
    assert not gg.check(repo).blocked
    (repo / "t.sh").write_text("#!/bin/sh\ntouch RAN\n")
    assert gg.check(repo).blocked, key
