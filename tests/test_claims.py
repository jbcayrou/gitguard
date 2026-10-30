"""gitguard's lists of claims about git, held to git itself.

Each closed list in gitguard.py says "git never does X here": a global flag
that does not move the gitdir (GLOBAL_FLAGS), the options of clone and
init (NEW_REPO_OPTIONS), the index extensions git requires
(KNOWN_REQUIRED_EXTENSIONS), the invocations run without a check
(passthrough), and the barrier of DESIGN-exec-path.md: git enters another
repository through a child process. Every one of them fell in a review
because nothing checked the claim itself, only the attacks known at the
time: [97] (`--bare` taken for inert), [86] (`commit` exempt from the
former switch), [98] (`--templ=`). Here
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
from tests.test_commands import EDITOR, _gitlink_in_head, _gitlink_in_head_volatile_zone, _typechange_to_repo


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


# ====================================== passthroughs that read no repository
@pytest.mark.parametrize("opt", [o[0] for o in gg_mod.PATH_QUERIES])
def test_path_query_passes_through_and_matches_git(gg: GG, repo: Path, opt: str) -> None:
    """PATH_QUERIES: `git --exec-path` (and `--html-path`, `--man-path`,
    `--info-path`) print and exit in handle_options, before any setup —
    the exec path's shell scripts start with `. "$(git --exec-path)/git-sh-setup"`.
    Through gitguard, in a never-trusted repository, the answer is git's."""
    (repo / "x").write_text("x\n")
    gg.git("config", "core.hooksPath", "/nowhere", cwd=repo)     # the repository is no longer trusted
    assert gg.check(repo).blocked
    r = gg.run("git", opt, cwd=repo)
    want = subprocess.run(["git", opt], cwd=repo, env=gg.env, capture_output=True, text=True)
    assert r.rc == 0 and r.out == want.stdout and want.stdout.strip(), (opt, r.text)
    assert gg.run("git", opt + "=/x", "status", cwd=repo).blocked     # the setting form is checked


# ================================ git enters a repository through a child
# DESIGN-exec-path.md: no route is guessed any more; the claim is that git
# enters another repository — a submodule, a planted `vendor/x` — through a
# child process, `<exec-path>/git`, which is gitguard. The same command, the
# same planting, with the wrapped exec path (the child refuses, the payload
# never runs) and the raw one (the positive control: the real git's child
# runs it). A planting and a command for each way the sandbox brings a
# gitlink: a tracked file replaced by a repository ([86]), a HEAD moved to a
# commit with a gitlink ([86]), `--submodule=diff` ([89]); and the planted
# gitdir hidden in a volatile zone of a real submodule's gitdir, where the
# marker must not cover it ([103]).
ENTRIES = {
    "typechange_commit_a": ("typechange", ["commit", "-a"]),
    "gitlink_in_head_partial_commit": ("gitlink_in_head", ["commit", "a"]),
    "gitlink_in_head_volatile_zone": ("volatile_zone", ["commit", "a"]),
}


def _planted(gg: GG, repo: Path, tmp_path: Path, planting: str) -> Path:
    mark = tmp_path / "RAN"
    if planting == "typechange":
        _typechange_to_repo(gg, repo, mark)
        return repo
    if planting == "volatile_zone":
        return _gitlink_in_head_volatile_zone(gg, tmp_path, mark)
    return _gitlink_in_head(gg, tmp_path, mark)


@pytest.mark.parametrize("form", sorted(ENTRIES))
def test_git_enters_a_planted_repository_through_a_child(gg: GG, repo: Path, tmp_path: Path,
                                                         form: str) -> None:
    """With gitguard at the exec path, the real git's own command does not
    run the planted repository's config: its child there is gitguard, which
    refuses a repository never trusted."""
    planting, cmd = ENTRIES[form]
    r = _planted(gg, repo, tmp_path, planting)
    gg.env["GIT_EDITOR"] = EDITOR
    subprocess.run(["git", *cmd], cwd=r, env=gg.env, capture_output=True)   # wrapped children
    assert not (tmp_path / "RAN").exists(), f"`git {' '.join(cmd)}` ran the planted config"


@pytest.mark.parametrize("form", sorted(ENTRIES))
def test_git_enters_control_raw_child_runs_it(gg: GG, repo: Path, tmp_path: Path, form: str) -> None:
    """Positive control: the same command with raw children runs it. If this
    fails, git enters this way in-process now, and the barrier is gone for
    that command: DESIGN-exec-path.md, section 6."""
    planting, cmd = ENTRIES[form]
    r = _planted(gg, repo, tmp_path, planting)
    gg.env["GIT_EDITOR"] = EDITOR
    subprocess.run(["git", *cmd], cwd=r, env=gg.raw_env, capture_output=True)
    assert (tmp_path / "RAN").exists(), f"git no longer enters with `git {' '.join(cmd)}`"


# Commands that read another repository in-process (repo_submodule_init),
# where no child process stands between git and that repository
# (DESIGN-exec-path.md, section 6). Two of them DO run the nested
# repository's config (its core.fsmonitor, on the index refresh): the
# barrier there is not the child but the fingerprint — a submodule is
# entered in-process only when it is *active*, which takes
# `submodule.<name>.url` or `.active` in `.git/config` (is_submodule_active
# reads the config, not .gitmodules), and `.git/config` is hashed; a
# planted repository under a tracked path that the sandbox cannot activate
# by name. A trusted `submodule.active` pathspec activates it for free:
# [126], the accepted limitation, its record below. Recorded here per
# command: whether the real git (raw children) runs the nested config, and
# that gitguard refuses the by-name activation before.
IN_PROCESS = {
    "ls_files": (["ls-files", "--recurse-submodules"], True),
    "grep": (["grep", "--recurse-submodules", "s"], True),
    "diff_submodule_log": (["diff", "--cached", "--submodule=log"], False),
    "rev_list_objects": (["rev-list", "--objects", "HEAD"], False),
}


@pytest.mark.parametrize("form", sorted(IN_PROCESS))
def test_in_process_entry_needs_an_activation_gitguard_refuses(gg: GG, repo: Path, tmp_path: Path,
                                                               form: str) -> None:
    mark = tmp_path / "RAN"
    _typechange_to_repo(gg, repo, mark)
    (repo / ".gitmodules").write_text('[submodule "f"]\n\tpath = f\n\turl = ./f\n')
    gg.git("config", "submodule.f.url", str(repo / "f"), cwd=repo)
    gg.git("config", "submodule.f.active", "true", cwd=repo)
    assert gg.git("add", "-A", cwd=repo).rc == 0
    assert not mark.exists(), "`git add -A` ran the planted config: test_first_add_does_not_execute"
    r = gg.check(repo)
    assert r.blocked and "config" in r.err, r.text          # the activation is a watched change
    cmd, runs = IN_PROCESS[form]
    gg.git(*cmd, cwd=repo)                                  # the real git, raw children
    assert mark.exists() == runs, (f"`git {' '.join(cmd)}` {'no longer runs' if runs else 'now runs'} "
                                   f"the nested config in-process: update IN_PROCESS and section 6")


def test_pathspec_activation_grep_tree_enters_in_process(gg: GG, repo: Path,
                                                         tmp_path: Path) -> None:
    """[126]: with a `submodule.active` pathspec already trusted (what `clone
    --recurse-submodules` writes), a gitlink in a tree object is an active
    submodule with no config write, and `grep --recurse-submodules <tree>`
    opens the planted gitdir in-process — no child runs, the wrap judges
    nothing. The real git runs its core.fsmonitor (positive control: the
    entry exists); through gitguard it does not: PINNED_CONFIG puts
    `core.fsmonitor=false` in GIT_CONFIG_PARAMETERS, which outranks the
    planted repository's config; GITGUARD_KEEP_FSMONITOR lets it through
    again. Every other in-process reader executes nothing of it. The
    control failing means git closed the entry ([126] moves to fixed);
    another reader executing means the pin's proof grew (a new entry)."""
    from tests.attacks._helpers import plant_active_gitlink
    mark = plant_active_gitlink(gg, repo, tmp_path, planting="tree")
    cmd = ["grep", "--recurse-submodules", "s", "HEAD"]
    r = subprocess.run(["git", *cmd], cwd=repo, env=gg.raw_env, capture_output=True)
    assert r.returncode == 0 and mark.exists(), "grep no longer enters in-process: [126] is closed, move it to fixed"
    mark.unlink()
    assert gg.run("git", *cmd, cwd=repo).rc == 0
    assert not mark.exists(), "the planted core.fsmonitor ran through gitguard: the pin is gone"
    gg.env["GITGUARD_KEEP_FSMONITOR"] = "1"
    assert gg.run("git", *cmd, cwd=repo).rc == 0
    assert mark.exists(), "GITGUARD_KEEP_FSMONITOR no longer lets the hook through: update its doc"
    del gg.env["GITGUARD_KEEP_FSMONITOR"]
    for cmd in (["grep", "--recurse-submodules", "s"], ["ls-files", "--recurse-submodules"],
                ["diff", "--cached", "--submodule=log"], ["rev-list", "--objects", "HEAD"],
                ["status"]):
        mark.unlink(missing_ok=True)
        subprocess.run(["git", *cmd], cwd=repo, env=gg.raw_env, capture_output=True)
        assert not mark.exists(), f"`git {' '.join(cmd)}` now executes the planted config: a new entry"


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


# Every call that takes a git out of its command's process tree —
# `daemonize()`, `setsid()`, `start_bg_command()` — as `<file>:<function>`
# from the inventory. keep_attached (DESIGN-exec-path.md 3.2, [117]) is a
# closed list of the two that git runs as a child of an ordinary user
# command and that run git children after detaching: their children would
# find the marker's process gone and judge as a user's command would. The
# rest detach and run no git afterwards, or are never a child of a judged
# command. Every caller must be classified here, so a future git that
# detaches somewhere new fails first. Not in the oracle: transport-helper.c
# forks twice (the two copy tasks of a bidirectional remote helper), but
# the parent waits for both (tloop_join/waitpid) — nothing leaves the tree.
DETACH = {
    "builtin/gc.c:cmd_gc":
        "gc --auto under gc.autoDetach: git runs it after a command; its gc/"
        "repack/prune are git children → keep_attached turns it --no-detach",
    "builtin/gc.c:maintenance_run_tasks":
        "maintenance run --detach: git >= 2.47 runs it after a command (cmd_"
        "maintenance -> here); its tasks are git children → keep_attached",
    "daemon.c:cmd_main":
        "git daemon: a server the user starts explicitly, never a child of an "
        "ordinary command; the repository it serves and that repository's git "
        "children get their own marker (TRANSPORT/SERVERS, 3.4), not an "
        "inherited one, so its detaching needs no keep_attached",
    "builtin/fsmonitor--daemon.c:try_to_run_foreground_daemon":
        "`fsmonitor--daemon run --detach`, setsid() then fsmonitor_run_daemon: "
        "listener, health and IPC threads in-process, no run_command/"
        "start_command/git_cmd anywhere after the detach (builtin/fsmonitor--"
        "daemon.c, compat/fsmonitor/): runs no git once detached",
    "builtin/fsmonitor--daemon.c:try_to_start_background_daemon":
        "`fsmonitor--daemon start` (a git child of `status` under core."
        "fsmonitor=true, judged by the wrap): start_bg_command of `run "
        "--detach`, waited for until ready (SBGR_READY); the only git it runs "
        "is that child, before it is detached; the detached one runs none",
}
KEEP_ATTACHED = {"builtin/gc.c:cmd_gc", "builtin/gc.c:maintenance_run_tasks"}


@pytest.mark.discovery
def test_keep_attached_covers_every_daemonizing_child() -> None:
    """[117] every caller of daemonize(), setsid() or start_bg_command()
    git's source names is classified: either a git keep_attached keeps
    attached (the two auto-run after an ordinary command, gc --auto and
    maintenance run --detach) or one that runs no git once detached. An
    unclassified caller is a future [117] (a git whose detached children
    would find the marker dead)."""
    callers = set(_inventory("detach"))
    assert callers == set(DETACH), (callers ^ set(DETACH))
    assert KEEP_ATTACHED <= callers


@pytest.mark.parametrize("cmd,detach,no_detach", [
    (["maintenance", "run", "--detach"], "--detach", "--no-detach"),
    (["gc", "--auto"], None, "gc.autoDetach=false"),
])
def test_keep_attached_disarms_the_detach(cmd: list[str], detach: str | None,
                                          no_detach: str) -> None:
    """keep_attached rewrites the two auto-run commands so they do not leave
    the tree: `maintenance run --detach` -> `--no-detach`, `gc` -> prefixed
    with `-c gc.autoDetach=false`. A command that does not daemonize is left
    untouched."""
    out = gg_mod.keep_attached(list(cmd), Path.cwd())
    assert no_detach in out
    if detach is not None:
        assert detach not in out
    assert gg_mod.keep_attached(["status"], Path.cwd()) == ["status"]


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
