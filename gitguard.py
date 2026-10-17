#!/usr/bin/env python3
"""gitguard — refuses to run git on a repository whose "trusted" files have
changed since the user last validated them.

Usage:
  gitguard               check the current repository (exit 1 if suspect or never trusted)
  gitguard trust         record the current state as the reference (+ backup)
  gitguard diff          show what differs from the reference
  gitguard restore [-y]  put the watched files back into the reference state
  gitguard git <args>    check, then run git; honours -C/--git-dir/--work-tree;
                         successful clone/init → automatic trust; a pure
                         branch-tracking addition (push -u…) is accepted on its
                         own; any other change is shown, then asked on the
                         terminal [y/N]
  gitguard list          registered repositories and their status
  gitguard forget <repo>... | --missing
  gitguard prune         = forget --missing
  gitguard retrust       re-validate unchanged repositories (after an upgrade)
  gitguard help

Alias:    alias git='gitguard git'      Wrapper: ln -s ~/bin/gitguard ~/bin/git
Env:      GITGUARD_STATE, GITGUARD_REAL_GIT, GITGUARD_PRUNE, GITGUARD_SCAN_TREE=1
          (search the tree for nested .git, costly, off by default),
          GITGUARD_ALLOW_REBASE_EXEC, GITGUARD_NO_PROMPT, GITGUARD_DEBUG, NO_COLOR

Threat model, design choices and vulnerability history: see CLAUDE.md.
"""
from __future__ import annotations

import difflib
import hashlib
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from functools import cached_property
from pathlib import Path
from typing import Iterator

FORMAT_VERSION = 4   # 4: symlink hashes include the target's content
REAL_GIT = os.environ.get("GITGUARD_REAL_GIT", "/usr/bin/git")
STATE = Path(os.environ.get("GITGUARD_STATE") or Path.home() / ".local/state/gitguard")
PRUNE_DIRS = set(os.environ.get(
    "GITGUARD_PRUNE", "node_modules .venv venv target build dist .cache").split())
INCLUDE_DEPTH = 10      # git: MAX_INCLUDE_DEPTH = 10
# GITGUARD_SCAN_TREE=1: walk the work tree looking for nested `.git`.
# Off by default: ~90 % of the cost on a large repository (0.6 s for 20k
# directories, 0.17 s on the Linux kernel), and the walk is only an early
# warning: git opens a nested repository only once a gitlink references it in
# the index (`index_gitlinks`, always read), and the first `git add -A` that
# creates this gitlink executes nothing by itself
# (tests/nested_git_is_a_threat.sh and test_first_add_does_not_execute).
# Without the scan, the command that FOLLOWS the `add -A` is refused instead
# of the `add` itself; only a hook or `!` alias of the trusted config that
# re-invokes git during that `add` escapes the wrapper (see CLAUDE.md).
# Still read without walking: `.gitmodules` and the gitlinks. A bare gitdir
# planted in a subdirectory [23] is no longer reported from the root, but
# `find_root` refuses it as soon as git is run from that directory, and
# `safe.bareRepository=explicit` (checked by `check_safe_bare`) makes git
# itself refuse.
SCAN_TREE = os.environ.get("GITGUARD_SCAN_TREE", "0") in ("1", "yes", "true")

# Volatile: what git rewrites during normal operation. Everything else in the
# gitdir is watched (deny-by-default inversion, see CLAUDE.md).
#
# These names are **anchored**: they only count directly under a gitdir root
# (the gitdir itself, or `modules/<x>/`, `worktrees/<x>/`, recognised by the
# presence of a HEAD or commondir file). Otherwise a submodule named `lfs` or
# `refs` would make its whole gitdir invisible — bypass found in review.
VOLATILE_DIRS = {"refs", "logs", "lfs", "rr-cache", "rebase-merge", "rebase-apply",
                 "sequencer", "filter-repo"}
VOLATILE_UNDER_OBJECTS = {"pack"}
VOLATILE_UNDER_OBJECTS_INFO = {"commit-graphs"}
VOLATILE_FILES = {"index", "HEAD", "ORIG_HEAD", "FETCH_HEAD", "MERGE_HEAD", "MERGE_MSG",
                  "MERGE_MODE", "MERGE_RR", "MERGE_AUTOSTASH", "AUTO_MERGE", "REBASE_HEAD",
                  "CHERRY_PICK_HEAD", "REVERT_HEAD", "SQUASH_MSG", "COMMIT_EDITMSG",
                  "TAG_EDITMSG", "packed-refs", "shallow", "gc.log", "gc.pid",
                  "commit-graph", "multi-pack-index", "locked"}
# Volatile files located elsewhere than a gitdir root, by relative path.
VOLATILE_RELPATHS = {"info/refs", "objects/info/packs", "objects/info/commit-graph",
                     "objects/info/multi-pack-index"}
# Rebase/cherry-pick todo lists live in volatile directories and may contain
# `exec <cmd>` lines that git runs: handled separately (check_rebase_todo),
# they cannot be part of the fingerprint since git rewrites them at every step.
TODO_FILES = ("rebase-merge/git-rebase-todo", "rebase-apply/git-rebase-todo",
              "sequencer/todo")
OBJECT_FANOUT = re.compile(r"^[0-9a-f]{2}$")


# ------------------------------------------------------------------ display
class Refuse(Exception):
    """Fatal error shown to the user, exit 1. The message is sanitized at
    construction: it almost always contains external paths."""

    def __init__(self, msg: str):
        super().__init__(san(msg))


class Style:
    """ANSI colours, active only when stderr is a terminal and NO_COLOR is unset.

    Rule: sanitize the data first (san), colour afterwards. Colour codes never
    go through san(), and external data is never interpolated raw into a
    message without going through san().
    """

    def __init__(self, enabled: bool):
        self.enabled = enabled

    def _wrap(self, code: str, text: str) -> str:
        return f"\x1b[{code}m{text}\x1b[0m" if self.enabled else text

    def red(self, t: str) -> str:    return self._wrap("31", t)
    def green(self, t: str) -> str:  return self._wrap("32", t)
    def yellow(self, t: str) -> str: return self._wrap("33", t)
    def cyan(self, t: str) -> str:   return self._wrap("36", t)
    def bold(self, t: str) -> str:   return self._wrap("1", t)


STYLE = Style(sys.stderr.isatty() and not os.environ.get("NO_COLOR"))
_CTRL = re.compile(r"[\x00-\x09\x0b-\x1f\x7f]")   # everything but \n (handled separately)
_SGR = re.compile(r"\x1b\[[0-9;]*m")                   # ESC [ … m: colour/bold, harmless


def san(s: object) -> str:
    """Neutralize control characters in text about to be displayed.

    SGR sequences (colours, bold, reset) are kept: they can neither clear the
    screen, nor move the cursor, nor fake a message — an attacker who colours
    a file name gains nothing. Any other control character (lone ESC, erase
    CSI, \\r, tab, \\x7f…) becomes "?". Newlines are preserved: a file name that
    contains one is already refused by check_structure; in a message they are
    intended.
    """
    text = str(s)
    out, pos = [], 0
    for m in _SGR.finditer(text):
        out.append(_CTRL.sub("?", text[pos:m.start()]))
        out.append(m.group(0))
        pos = m.end()
    out.append(_CTRL.sub("?", text[pos:]))
    return "".join(out)


def err(msg: str) -> None:
    """Write an already composed message (sanitized data, colours included)."""
    print(msg, file=sys.stderr)


def _tag(color, mark: str, msg: str) -> None:
    err(f"{color(STYLE.bold(mark + ' gitguard:'))} {san(msg)}")


def info(msg: str) -> None:
    _tag(STYLE.green, "✓", msg)


def warn(msg: str) -> None:
    _tag(STYLE.yellow, "!", msg)


def fail(msg: str) -> None:
    _tag(STYLE.red, "✗", msg)


def hint(msg: str) -> None:
    err(f"  {STYLE.cyan(san(msg))}")


def rule() -> None:
    err(STYLE.red("─" * 56))


# ------------------------------------------------------------ config parser
_SECTION = re.compile(r'^\s*\[\s*([^\s\]"]+)(?:\s+"((?:[^"\\]|\\.)*)")?\s*\]')


def parse_git_config(path: Path) -> list[tuple[str, str, str]]:
    """Return [(section, key, value)], section lower-cased with its subsection
    ("includeIf.gitdir:x"), key lower-cased. Handles comments, quotes, escapes
    and line continuations. Never via `git config`: git would honour the very
    config we are trying to judge."""
    out: list[tuple[str, str, str]] = []
    try:
        text = path.read_text(errors="surrogateescape")
    except OSError:
        return out
    section = ""
    lines = text.split("\n")
    i = 0
    while i < len(lines):
        line = lines[i]
        # Continuation: a trailing UNESCAPED `\` (odd number of `\`);
        # `foo\\` is the value `foo\` for git, not a continuation.
        while _odd_trailing_backslashes(line) and i + 1 < len(lines):
            i += 1
            line = line[:-1] + lines[i]
        i += 1
        s = line.strip()
        if not s or s[0] in "#;":
            continue
        m = _SECTION.match(line)
        if m:
            section = m.group(1).lower()
            if m.group(2) is not None:
                section += "." + m.group(2).replace('\\"', '"').replace("\\\\", "\\")
            # git accepts a key right after `]` on the same line
            # (`[core]hooksPath = x`): dropping it hid an executed path. [21]
            line = line[m.end():]
            s = line.strip()
            if not s or s[0] in "#;":
                continue
        if "=" in line:
            key, _, raw = line.partition("=")
            value = _unquote(raw)
        else:
            key, value = s, "true"
        out.append((section, key.strip().lower(), value))
    return out


def _odd_trailing_backslashes(line: str) -> bool:
    n = len(line) - len(line.rstrip("\\"))
    return n % 2 == 1


def _unquote(raw: str) -> str:
    """Config value: outer whitespace outside quotes stripped, quotes removed,
    escapes resolved, trailing comment (# or ;) outside quotes ignored.
    Like git: whitespace inside quotes is kept, whitespace between two
    segments is collapsed according to the raw text."""
    res: list[str] = []
    i, quoted = 0, False
    raw = raw.strip()
    while i < len(raw):
        ch = raw[i]
        if ch == "\\" and i + 1 < len(raw):
            nxt = raw[i + 1]
            res.append({"n": "\n", "t": "\t", "b": "\b"}.get(nxt, nxt))
            i += 2
            continue
        if ch == '"':
            quoted = not quoted
        elif ch in "#;" and not quoted:
            break
        elif ch in " \t" and not quoted:
            # git collapses any run of unquoted whitespace to a single space
            if res and res[-1] != " ":
                res.append(" ")
        else:
            res.append(ch)
        i += 1
    value = "".join(res)
    return value if raw.rstrip().endswith('"') else value.rstrip()


# ---------------------------------------------------------- repo / gitdir
def key_for(root: Path) -> Path:
    """State key of a repository: first 16 hex digits of the sha256 of its canonical root."""
    return STATE / hashlib.sha256(str(root).encode()).hexdigest()[:16]


@dataclass
class Repo:
    root: Path        # work tree root, canonical
    gitdir: Path      # real gitdir (resolved if gitfile)
    common: Path      # commondir (== gitdir outside a linked worktree)

    @property
    def key(self) -> Path:
        return key_for(self.root)

    @cached_property
    def nested(self) -> list[Path]:
        """Nested `.git` in the tree (a single walk per invocation)."""
        return nested_gits(self.root)

    @cached_property
    def gitfiles(self) -> list[Path]:
        """Every nested `.git` to check: those found in the tree AND those
        referenced by index gitlinks — a gitlink may point into a pruned
        directory (`node_modules/pkg`) where a redirected gitfile was neither
        checked nor hashed. [24]"""
        out = set(self.nested)
        for rel in index_gitlinks(self.gitdir, Path(str(self.key) + ".idx")):
            g = self.root / rel / ".git"
            if g.exists() or g.is_symlink():
                out.add(g)
        return sorted(out)


def is_bare_gitdir(d: Path) -> bool:
    """What git calls is_git_directory: HEAD (file) + objects/ + refs/.
    This is how git recognises a bare repository — or any directory a
    container has stuffed with these three names."""
    return (d / "HEAD").is_file() and (d / "objects").is_dir() and (d / "refs").is_dir()


def find_root(cwd: Path) -> Path | None:
    """Walk up to a .git WITHOUT calling git (git would read the booby-trapped config).

    Same order as git at each level: `<d>/.git` first, then "is `<d>` itself a
    gitdir?". That second test was missing: a bare gitdir planted in `src/`
    was discovered by git before the parent's `.git`, which gitguard checked
    instead. [23] Bare repositories are not handled: refuse."""
    if os.environ.get("GIT_DIR"):
        # --git-dir / GIT_DIR: git discovers nothing, the tree is GIT_WORK_TREE,
        # else core.worktree (relative to the gitdir), else the cwd. Always
        # taking the cwd made gitguard check all of $HOME. [28]
        wt = os.environ.get("GIT_WORK_TREE")
        if wt:
            return Path(wt).resolve()
        gd = Path(os.environ["GIT_DIR"])
        for section, key, value in parse_git_config(gd / "config"):
            if section == "core" and key == "worktree":
                return (gd / value).resolve()
        return cwd.resolve()
    d = cwd.resolve()
    while True:
        if (d / ".git").exists() or (d / ".git").is_symlink():
            return d
        if is_bare_gitdir(d):
            raise Refuse(f"bare gitdir found before any .git: {d} — bare repository (not "
                         f"handled by gitguard) or booby-trapped directory. Run /usr/bin/git "
                         f"explicitly if intended; {SAFE_BARE_HINT}.")
        if d.parent == d:
            return None
        d = d.parent


def read_gitfile(p: Path) -> Path:
    for line in p.read_text(errors="surrogateescape").splitlines():
        if line.startswith("gitdir: "):
            target = Path(line[8:].strip())
            return (target if target.is_absolute() else p.parent / target).resolve()
    raise Refuse(f"{p}: invalid .git file")


def open_repo(root: Path) -> Repo:
    g = Path(os.environ["GIT_DIR"]).resolve() if os.environ.get("GIT_DIR") else root / ".git"
    if g.is_symlink():
        raise Refuse(f"{g} is a symlink")
    if g.is_file():
        # Legitimate for worktrees/submodules, but never INSIDE the work tree.
        target = read_gitfile(g)
        if root in target.parents or target == root:
            raise Refuse(f"{g} points inside the work tree ({target})")
        if not target.is_dir():
            raise Refuse(f"gitdir not found: {target}")
        g = target
    if not g.is_dir():
        raise Refuse(f"{g} is not a directory")
    common = g
    cd = g / "commondir"
    if cd.is_file():
        common = (g / cd.read_text().strip()).resolve()
    return Repo(root, g.resolve(), common)


# ------------------------------------------------------- structural checks
def gitmodules_paths(root: Path) -> list[str]:
    return [v for s, k, v in parse_git_config(root / ".gitmodules")
            if s.startswith("submodule.") and k == "path"]


def nested_gits(root: Path) -> list[Path]:
    """Every nested .git: found in the tree (outside pruned dirs) AND declared
    in .gitmodules (even inside a pruned directory: git will descend there). A
    directory that is itself a bare gitdir (HEAD + objects/ + refs/) counts
    too: git uses it as soon as git is run from that directory. [23]

    No `onerror`: an unreadable directory in the tree is ignored (git cannot
    read it either); the dangerous case — a gitlink to that directory — is
    covered by `index_gitlinks`, which does not depend on the walk.

    The disk walk only happens with `GITGUARD_SCAN_TREE=1` (see SCAN_TREE);
    the paths from `.gitmodules` are always checked."""
    found: set[Path] = set()
    for dirpath, dirnames, filenames in (os.walk(root) if SCAN_TREE else ()):
        d = Path(dirpath)
        if d != root and "HEAD" in filenames and is_bare_gitdir(d):
            found.add(d)
            dirnames[:] = []
            continue
        keep = []
        for name in dirnames:
            if name in PRUNE_DIRS or (d == root and name == ".git"):
                continue
            if name == ".git":
                found.add(d / name)
                continue
            keep.append(name)
        dirnames[:] = keep
        if ".git" in filenames and d != root:
            found.add(d / ".git")
    for rel in gitmodules_paths(root):
        p = root / rel / ".git"
        if p.exists() or p.is_symlink():
            found.add(p)
    return sorted(found)


def index_gitlinks(gitdir: Path, cache: Path | None = None) -> list[str]:
    """Paths recorded as gitlinks (mode 160000) in `.git/index`, read by
    parsing the file — never via `git`, which would read the config we judge.

    This is the criterion that matters: a nested repository is only dangerous
    if a gitlink references it, and conversely a gitlink may point into a
    directory pruned by GITGUARD_PRUNE, invisible to the disk scan.

    `cache` (`<key>.idx` in the state dir, out of the container's reach)
    memoizes the result keyed by the file's sha256: the Python parse costs
    ~40 ms for 96k entries (Linux kernel), the hash 4 ms. A modified — or
    forged — index has another sha256 and is re-parsed; an unreadable or
    inconsistent cache is ignored. Nothing is cached when the parser refuses."""
    p = gitdir / "index"
    try:
        data = p.read_bytes()
    except OSError:
        return []
    if len(data) < 12 or data[:4] != b"DIRC":
        return []
    digest = hashlib.sha256(data).hexdigest()
    if cache is not None:
        try:
            c = json.loads(cache.read_text())
            if (isinstance(c, dict) and c.get("sha256") == digest
                    and isinstance(c.get("gitlinks"), list)
                    and all(isinstance(x, str) for x in c["gitlinks"])):
                return list(c["gitlinks"])
        except (OSError, ValueError):
            pass
    out = _parse_index_gitlinks(data, p)
    if cache is not None:
        try:
            tmp = Path(str(cache) + ".tmp")
            tmp.write_text(json.dumps({"sha256": digest, "gitlinks": out}))
            os.replace(tmp, cache)
        except OSError:
            pass
    return out


def _parse_index_gitlinks(data: bytes, p: Path) -> list[str]:
    version = int.from_bytes(data[4:8], "big")
    count = int.from_bytes(data[8:12], "big")
    if version not in (2, 3, 4):
        raise Refuse(f"unsupported git index version ({version}): cannot check "
                     f"nested repositories of {p}")
    out, off, prev = [], 12, b""
    for _ in range(count):
        if off + 62 > len(data):
            break
        mode = int.from_bytes(data[off + 24:off + 28], "big")
        flags = int.from_bytes(data[off + 60:off + 62], "big")
        cur = off + 62
        if flags & 0x4000:               # extended entry (v3+)
            cur += 2
        # Name length: git reads `flags & 0xFFF` and only looks for the NUL
        # when that value is saturated (0xFFF). Stopping at the first NUL, as
        # the parser used to, allowed desynchronising it (long announced name,
        # early NUL) and hiding a gitlink that git honours. [14]
        namelen = flags & 0xFFF
        if version == 4:
            strip, cur = _decode_varint(data, cur)
            copy = len(prev) - strip
            if copy < 0:
                raise Refuse(f"corrupt git index (inconsistent v4 prefix): {p}")
            if namelen == 0xFFF:
                end = data.index(b"\0", cur)
            else:
                end = cur + namelen - copy
            name = prev[:copy] + data[cur:end]
            off = end + 1
        else:
            if namelen == 0xFFF:
                end = data.index(b"\0", cur)
            else:
                end = cur + namelen
            name = data[cur:end]
            # Total entry length, padded to a multiple of 8 from its START
            # (not from the start of the name): (base + len + 8) & ~7.
            off += ((cur - off) + (end - cur) + 8) & ~7
        if end > len(data) or b"\0" in name or data[end:end + 1] != b"\0":
            raise Refuse(f"corrupt or forged git index (inconsistent name length): {p}")
        prev = name
        if mode & 0xF000 == 0xE000:      # 0160000: gitlink
            out.append(name.decode(errors="surrogateescape"))
    return out


def _decode_varint(data: bytes, off: int) -> tuple[int, int]:
    c = data[off]; off += 1
    val = c & 127
    while c & 128:
        val += 1
        c = data[off]; off += 1
        val = (val << 7) + (c & 127)
    return val, off


def check_split_index(repo: Repo) -> None:
    """core.splitIndex: the entries (hence the gitlinks) live in a
    `sharedindex.<sha>` file that index_gitlinks does not read, and that git
    rewrites (it would alert permanently). Explicit refusal rather than
    accidentally closed. [31]"""
    if any(repo.gitdir.glob("sharedindex.*")):
        raise Refuse(f"core.splitIndex not supported (sharedindex.* in {repo.gitdir}): "
                     f"run `git update-index --no-split-index` and retry")


def nested_repo_hint(n: Path) -> str:
    return (f"nested repository: {n} — git will execute its config as soon as a gitlink "
            f"for this directory exists in the index (a plain `git add -A` creates one). "
            f"If this is intended, add the directory to GITGUARD_PRUNE.")


def check_rebase_todo(repo: Repo) -> None:
    """Rebase/cherry-pick todo lists live in volatile directories (git rewrites
    them at every step, so they cannot be part of the fingerprint) but accept
    `exec <cmd>` lines that git runs verbatim. The container can inject some
    during an in-progress rebase: refuse their presence, unless the user runs
    `--exec` rebases themselves."""
    if os.environ.get("GITGUARD_ALLOW_REBASE_EXEC"):
        return
    for rel in TODO_FILES:
        p = repo.gitdir / rel
        if not p.is_file():
            continue
        for line in p.read_text(errors="surrogateescape").splitlines():
            word = line.strip().split(" ", 1)[0]
            if word in ("exec", "x"):
                raise Refuse(
                    f"`exec` line in {p}: git would run it on the next "
                    f"`rebase --continue`. Check this file; if this rebase is really "
                    f"yours, retry with GITGUARD_ALLOW_REBASE_EXEC=1.")


def check_structure(repo: Repo, refs: list[tuple[str, Path]]) -> None:
    check_split_index(repo)
    # Every nested .git — found in the tree or referenced by an index gitlink
    # (independent of GITGUARD_PRUNE: covers node_modules/, build/…) — must be
    # a file pointing under .git/modules (submodule) or under .git/worktrees
    # (linked worktree stored inside the tree, e.g. `.worktrees/x`).
    for n in repo.gitfiles:
        if n.is_symlink():
            raise Refuse(f"nested .git is a symlink: {n}")
        if n.is_dir():
            if n.name != ".git":
                raise Refuse(f"bare gitdir in the tree: {n} (HEAD + objects/ + refs/) — git "
                             f"would use it instead of the repository as soon as git is run "
                             f"from that directory. If intended, add it to GITGUARD_PRUNE.")
            # Declared in .gitmodules or not: a nested .git directory is never
            # a real submodule (that one has a .git file pointing under
            # .git/modules), and git reads its config as soon as a gitlink
            # references it in the index.
            raise Refuse(nested_repo_hint(n))
        target = read_gitfile(n)
        if not any(repo.common / d in target.parents for d in ("modules", "worktrees")):
            raise Refuse(f"{n} points outside .git/modules and .git/worktrees: {target}")
    check_rebase_todo(repo)
    # Control characters in a name: fake line / spoofed display. Only names
    # that enter the fingerprint (hence get displayed) matter: the non-volatile
    # gitdir, walked once even when commondir == gitdir. Descending into
    # objects/ cost ~200 ms on 30k loose objects, and a detached `gc --auto`
    # deleting objects/xx during the walk caused a wrongful refusal.
    def bad(name: str) -> bool:
        return bool(_CTRL.search(name)) or "\n" in name
    for base in {repo.gitdir, repo.common}:
        if bad(str(base)):
            raise Refuse(f"control character in a file name: {base}")
        for rel, p in gitdir_paths(base):
            if bad(rel):
                raise Refuse(f"control character in a file name: {p}")
    for _, root in refs:
        for p in walk_all(root):
            if bad(str(p)):
                raise Refuse(f"control character in a file name: {p}")
    # Symlinks in the first two levels of the gitdir (refs → ~/.config…)
    for p in repo.gitdir.iterdir():
        if p.is_symlink():
            raise Refuse(f"symlink in the gitdir: {p}")
        if p.is_dir():
            for q in p.iterdir():
                if q.is_symlink():
                    raise Refuse(f"symlink in the gitdir: {q}")
    # Ownership / permissions of the key files
    me = os.getuid()
    for p in [b / n for b in {repo.gitdir, repo.common} for n in ("config", "hooks")] + \
             [q for b in {repo.gitdir, repo.common} for q in (b / "hooks").glob("*")]:
        try:
            st = p.lstat()
        except OSError:
            continue
        if st.st_uid != me or (st.st_mode & stat.S_IWOTH):
            raise Refuse(f"suspicious owner/permissions: {p}")


def walk_all(base: Path) -> Iterator[Path]:
    if base.is_symlink() or base.is_file():
        yield base
        return
    for dirpath, dirnames, filenames in os.walk(base, onerror=_walk_error):
        for name in dirnames:
            if (Path(dirpath) / name).is_symlink():
                yield Path(dirpath) / name
        for name in filenames:
            yield Path(dirpath) / name


# ------------------------------------------------ paths referenced by config
def xdg_config_home() -> Path:
    return Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")


def global_config_files() -> list[Path]:
    """System and global config files git may read. Deliberately broad
    (GIT_CONFIG_GLOBAL *and* ~/.gitconfig *and* XDG): watching one file too
    many costs nothing, missing one is a bypass [16]."""
    out = [Path(os.environ.get("GIT_CONFIG_SYSTEM") or "/etc/gitconfig"), Path.home() / ".gitconfig"]
    if os.environ.get("GIT_CONFIG_GLOBAL"):
        out.append(Path(os.environ["GIT_CONFIG_GLOBAL"]))
    out.append(xdg_config_home() / "git/config")
    return out


SAFE_BARE_HINT = ("`git config --global safe.bareRepository explicit`: git then refuses "
                  "to discover a bare gitdir planted in a subdirectory [23], even from a "
                  "tool that does not go through gitguard")


def safe_bare_explicit() -> bool:
    """`safe.bareRepository = explicit` in the system or global config, read
    with our parser (never `git config`, which would honour the judged config).
    Last value wins, as for git."""
    value = None
    for f in global_config_files():
        for section, key, v in parse_git_config(f):
            if section == "safe" and key == "barerepository":
                value = v
    return value is not None and value.strip().lower() == "explicit"


def check_safe_bare() -> None:
    """Warn (without refusing) if safe.bareRepository is not `explicit`.
    Called when the user reads the output: trust, retrust, list. Not on
    every git command: a warning repeated a hundred times ends up ignored."""
    if not safe_bare_explicit():
        warn(f"safe.bareRepository is not `explicit` in the global config; "
             f"recommended: {SAFE_BARE_HINT}")


def config_refs(repo: Repo) -> list[tuple[str, Path]]:
    """Paths outside the gitdir that the config makes git execute or read:
    core.hooksPath, include.path (recursive), and any token of a value that
    exists as a path. Returns [(scope, path)] with scope 'wt' (under the root)
    or 'ext' (elsewhere, writable). Plus the tree files that drive git: root
    gitfile, .gitmodules, each submodule's gitfile."""
    out: dict[Path, str] = {}

    def add(literal: Path, p: Path, allow_dir: bool = False) -> None:
        if not (p.exists() or p.is_symlink()):
            return
        # git executes files. A directory is only loaded by the keys that read
        # its content (DIR_KEYS); elsewhere it is a program argument
        # (`safe.directory = ~/projects`, `remote.origin.url = /local/repo`,
        # `!make -C src`) and fingerprinting it alerted on every neighbouring
        # file — and `restore` deleted there. [25]
        if p.is_dir() and not allow_dir:
            return
        # A referenced path reached through a symlink is refused: resolving the
        # link would pull its target (e.g. $HOME) into the fingerprint, and
        # `restore` would delete "what was added" over there.
        if literal.is_symlink() or any(q.is_symlink() for q in literal.parents
                                       if repo.root in q.parents or q == repo.root):
            raise Refuse(f"path referenced by the config reached through a symlink: {literal}")
        for base in (repo.gitdir, repo.common):
            if p == base or base in p.parents:
                # Covered by walk_gitdir… except in a volatile zone (logs/,
                # refs/, objects/pack…), which nobody fingerprints. No
                # legitimate config points there: refuse. [22]
                if gitdir_excluded(p, base):
                    raise Refuse(f"path referenced by the config lies in a volatile zone "
                                 f"of the gitdir (cannot be watched): {literal}")
                return
        if p == repo.root:
            return
        if repo.root in p.parents:
            out[p] = "wt"
        elif os.access(p, os.W_OK):
            out[p] = "ext"

    # .lfsconfig: git-lfs reads lfs.customtransfer.*.path from it (a program it runs). [34]
    for special in [repo.root / ".git", repo.root / ".gitmodules", repo.root / ".lfsconfig"]:
        if special.is_file():
            out[special] = "wt"
    for n in repo.gitfiles:
        if n.is_file():
            out[n] = "wt"

    # Config files git will read: local, the main repository's (a linked
    # worktree has no `config` of its own and uses commondir/config), then
    # system and global — their values also name paths the container can
    # write (global core.hooksPath, global include.path…).
    queue = [repo.gitdir / "config", repo.gitdir / "config.worktree",
             repo.common / "config", repo.common / "config.worktree",
             *global_config_files()]
    seen: set[Path] = set()
    # +1: the first round consumes the base files; git then follows
    # INCLUDE_DEPTH levels of includes. With range(INCLUDE_DEPTH) the 10th
    # level was hashed but never parsed. [17]
    for _ in range(INCLUDE_DEPTH + 1):
        nxt: list[Path] = []
        for cf in queue:
            if cf in seen or not cf.is_file():
                continue
            seen.add(cf)
            for section, key, value in parse_git_config(cf):
                if (section, key) in DIR_KEYS:
                    add(*_expand2(value, repo.root), allow_dir=True)
                elif section.startswith("include") and key == "path":
                    literal, p = _expand2(value, cf.parent)
                    if p.is_file():
                        nxt.append(p)
                    add(literal, p)
                else:
                    for tok in _value_tokens(value):
                        if tok and tok not in (".", "..") and not tok.startswith("-"):
                            add(*_expand2(tok, repo.root))
        queue = nxt
    return sorted(((scope, p) for p, scope in out.items()), key=lambda t: str(t[1]))


# Keys whose designated directory git reads the content of (hooks executed,
# hooks copied into every new repository). For any other value, only files
# count.
DIR_KEYS = {("core", "hookspath"), ("init", "templatedir")}


def _value_tokens(value: str) -> set[str]:
    """Path candidates of a config value: whitespace split, sh-style split (a
    quoted path, `!"./my tool.sh"`, is a single word for git, which hands the
    value to the shell) and the whole value (programs run without a shell).
    An unrecognised path with spaces went unwatched while git executed it."""
    toks = set(value.split())
    try:
        toks |= set(shlex.split(value))
    except ValueError:
        pass                              # unbalanced quotes: sh would refuse too
    toks.add(value.strip())
    return {t.lstrip("!").strip("\"'") for t in toks}


def _expand2(value: str, base: Path) -> tuple[Path, Path]:
    """(literal path, canonical path) — the literal detects symlinks, the
    canonical one is hashed."""
    if value.startswith("~/"):
        literal = Path.home() / value[2:]
    else:
        p = Path(value)
        literal = p if p.is_absolute() else base / p
    return literal, literal.resolve()


# -------------------------------------------------------------- fingerprint
@dataclass(frozen=True)
class Entry:
    scope: str        # local | common | wt | ext | global
    path: str         # relative to the scope base (ext/global: absolute)
    kind: str         # f | l
    mode: str
    sha: str


def _hash_into(h: "hashlib._Hash", p: Path) -> None:
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)


def _hash_file(p: Path) -> tuple[str, str, str] | None:
    """(kind, mode, sha) of a watched file or symlink; None otherwise
    (FIFO, socket, directory…)."""
    st = p.lstat()
    if stat.S_ISLNK(st.st_mode):
        # A link is fingerprinted by its target string AND by the content of
        # the file it designates: git executes that content, which may live
        # outside any watched zone (`.git/logs/`, a script in the tree,
        # ~/dotfiles…). A link to a directory is refused: its whole content
        # would escape the fingerprint (`.git/modules/x/hooks → elsewhere`). [22]
        h = hashlib.sha256(b"symlink:" + os.readlink(p).encode(errors="surrogateescape"))
        try:
            tst = os.stat(p)
        except OSError:
            tst = None                   # dangling link: nothing executable behind it
        if tst is not None and stat.S_ISDIR(tst.st_mode):
            raise Refuse(f"symlink to a directory in a watched zone: {p}")
        if tst is not None and stat.S_ISREG(tst.st_mode):
            h.update(b"\0target:")
            _hash_into(h, p)
        return "l", "l", h.hexdigest()
    if not stat.S_ISREG(st.st_mode):
        return None
    h = hashlib.sha256()
    _hash_into(h, p)
    return "f", f"{stat.S_IMODE(st.st_mode):o}", h.hexdigest()


def _mk(scope: str, rel: str, p: Path) -> Entry | None:
    r = _hash_file(p)
    return Entry(scope, rel, *r) if r else None


def _child_root(d: Path, parent_root: Path) -> Path:
    """Closest gitdir root of `d`, knowing its parent's. A nested gitdir
    (`modules/<name>`, `worktrees/<name>`, the name may contain `/`) is
    recognised by its HEAD or commondir — but only under `modules/` or
    `worktrees/` of a root: a forged `.git/hooks/HEAD` turned `hooks/` into a
    root and made its `refs/`, `logs/`, `HEAD`… invisible. [29]"""
    rel = d.relative_to(parent_root).parts
    if (len(rel) >= 2 and rel[0] in ("modules", "worktrees")
            and ((d / "HEAD").exists() or (d / "commondir").exists())):
        return d
    return parent_root


def _zone(d: Path, root: Path) -> tuple[bool, bool, bool]:
    """Position of `d` relative to its gitdir root: (is the root, is its
    `objects/`, is its `objects/info/`). Volatile exclusions only apply at
    these positions — a submodule named `refs` or `pack` must not vanish from
    the fingerprint."""
    at_root = d == root
    in_objects = d.name == "objects" and d.parent == root
    in_objects_info = d.name == "info" and d.parent.name == "objects" and d.parent.parent == root
    return at_root, in_objects, in_objects_info


def _volatile_dir(name: str, at_root: bool, in_objects: bool, in_objects_info: bool) -> bool:
    return ((at_root and name in VOLATILE_DIRS)
            or (in_objects and (name in VOLATILE_UNDER_OBJECTS or bool(OBJECT_FANOUT.match(name))))
            or (in_objects_info and name in VOLATILE_UNDER_OBJECTS_INFO))


def _volatile_file(name: str, rel: str, at_root: bool, is_symlink: bool) -> bool:
    """`rel` is relative to the closest gitdir root (not to the base): a
    submodule's `info/refs` is `modules/<x>/info/refs` seen from the base, and
    `git gc` in that submodule used to alert. [26]"""
    if is_symlink:
        return False                     # a symlink is always an entry, even *.lock
    return (name.endswith(".lock")
            or (at_root and (name in VOLATILE_FILES or name.startswith("BISECT_")))
            or rel in VOLATILE_RELPATHS)      # rel: relative to the closest root [26]


def gitdir_paths(base: Path) -> Iterator[tuple[str, Path]]:
    """(relative path, path) of everything the gitdir contains outside the
    volatile zones: files and symlinks (a symlink to a directory is an entry,
    never followed). The only walk of the gitdir — fingerprint and name scan
    both use it. The rules live in _volatile_dir/_volatile_file, shared with
    gitdir_excluded: two copies of the same rule had drifted apart ([22])."""
    roots: dict[Path, Path] = {base: base}     # directory → closest gitdir root
    for dirpath, dirnames, filenames in os.walk(base, onerror=_walk_error):
        d = Path(dirpath)
        root = roots[base] if d == base else _child_root(d, roots[d.parent])
        roots[d] = root
        zone = _zone(d, root)
        prefix = "" if d == base else str(d.relative_to(base)) + "/"
        rprefix = "" if d == root else str(d.relative_to(root)) + "/"
        keep = []
        for name in dirnames:
            if (d / name).is_symlink():
                filenames.append(name)        # a symlink is an entry
            elif not _volatile_dir(name, *zone):
                keep.append(name)
        dirnames[:] = keep
        for name in filenames:
            if not _volatile_file(name, rprefix + name, zone[0], (d / name).is_symlink()):
                yield prefix + name, d / name


def walk_gitdir(base: Path, scope: str) -> Iterator[Entry]:
    """Fingerprint of the gitdir: everything but the volatile (deny-by-default)."""
    for rel, path in gitdir_paths(base):
        e = _mk(scope, rel, path)
        if e:
            yield e


def gitdir_excluded(p: Path, base: Path) -> bool:
    """True if `p` (under `base`, a gitdir) falls in a zone that walk_gitdir
    does not fingerprint. Used to never believe "covered by the manifest" for
    a path that is not."""
    try:
        parts = p.relative_to(base).parts
    except ValueError:
        return False
    cur = root = base
    for i, name in enumerate(parts):
        last = i == len(parts) - 1
        zone = _zone(cur, root)
        nxt = cur / name
        if (not last or nxt.is_dir()) and _volatile_dir(name, *zone):
            return True
        if last and _volatile_file(name, str(nxt.relative_to(root)), zone[0], nxt.is_symlink()):
            return True
        cur = nxt
        if cur.is_dir():
            root = _child_root(cur, root)
    return False


def _walk_error(exc: OSError) -> None:
    """os.walk swallows errors by default: a directory made unreadable
    (chmod 0300) would silently become empty while git can still execute what
    it contains. Refuse rather than ignore.

    Exception: a directory that **vanished** during the walk (git gc, a rebase
    finishing) really is empty — it holds nothing git could execute. Treating
    it as unreadable caused wrongful refusals."""
    if isinstance(exc, FileNotFoundError):
        return
    raise Refuse(f"unreadable directory, cannot check: {exc.filename} ({exc.strerror})")


def walk_tree(scope: str, base: Path, start: Path) -> Iterator[Entry]:
    for p in walk_all(start):
        rel = str(p.relative_to(base)) if scope == "wt" else str(p)
        e = _mk(scope, rel, p)
        if e:
            yield e


def manifest(repo: Repo, refs: list[tuple[str, Path]]) -> dict[tuple[str, str], Entry]:
    entries: list[Entry] = list(walk_gitdir(repo.gitdir, "local"))
    if repo.common != repo.gitdir:
        entries += walk_gitdir(repo.common, "common")
    for scope, p in refs:
        entries += walk_tree(scope, repo.root, p)
    for f in [*global_config_files(), xdg_config_home() / "git/attributes"]:
        if f.is_file():
            e = _mk("global", str(f), f)
            if e:
                entries.append(e)
    return {(e.scope, e.path): e for e in entries}


# -------------------------------------------------------------------- state
def scope_base(repo: Repo, scope: str) -> Path:
    return {"local": repo.gitdir, "common": repo.common, "wt": repo.root}.get(scope, Path("/"))


@dataclass
class Manifest:
    """Recorded trust state. `current` false = written by an earlier version
    (or the bash format): to be re-validated, never compared."""
    version: int
    root: str | None
    refs: list[tuple[str, Path]]            # roots designated by the trusted config
    entries: dict[tuple[str, str], Entry]

    @property
    def current(self) -> bool:
        return self.version == FORMAT_VERSION


def load_manifest(key: Path) -> Manifest | None:
    """None if the repository was never trusted; a non-`current` Manifest if
    the state exists but in an earlier format."""
    if not key.is_file():
        return None
    try:
        data = json.loads(key.read_text())
        version = int(data.get("version") or 1)
        if version != FORMAT_VERSION:
            return Manifest(version, None, [], {})
        entries = {(e["scope"], e["path"]): Entry(**e) for e in data["entries"]}
        refs = [(sc, Path(p)) for sc, p in data.get("refs", [])]
        return Manifest(version, data.get("root"), refs, entries)
    except (json.JSONDecodeError, TypeError, KeyError, ValueError, AttributeError):
        return Manifest(1, None, [], {})     # legacy bash format


def save_trust(repo: Repo, refs: list[tuple[str, Path]] | None = None,
               man: dict[tuple[str, str], Entry] | None = None) -> None:
    """Record `man` as the reference. When the caller has already computed and
    shown the state (prompt, auto-accept), it passes it in: we validate
    exactly what was seen, not a recomputed state the container could have
    altered in the meantime."""
    if refs is None:
        refs = config_refs(repo)
        check_structure(repo, refs)
    if man is None:
        man = manifest(repo, refs)
    STATE.mkdir(parents=True, exist_ok=True)
    STATE.chmod(0o700)
    key = repo.key
    tmp = Path(str(key) + ".tmp")
    tmp.write_text(json.dumps({
        "version": FORMAT_VERSION, "root": str(repo.root),
        "created": time.strftime("%Y-%m-%dT%H:%M:%S"),
        # Roots designated by the trusted config: the only zones where
        # `restore` allows itself to delete (outside the gitdir).
        "refs": [[sc, str(p)] for sc, p in refs],
        "entries": [e.__dict__ for e in sorted(man.values(), key=lambda e: (e.scope, e.path))],
    }, indent=1, ensure_ascii=False))
    # The backup is built alongside then swapped in: a crash midway leaves the
    # old state intact, never a manifest without its backup.
    bak = Path(str(key) + ".d")
    new = Path(str(key) + ".d.tmp")
    shutil.rmtree(new, ignore_errors=True)
    new.mkdir()
    (new / ".root").write_text(str(repo.root) + "\n")
    for (scope, rel), e in man.items():
        if scope == "global":
            continue
        src = scope_base(repo, scope) / rel
        dst = new / scope / rel.lstrip("/")
        dst.parent.mkdir(parents=True, exist_ok=True)
        _copy_entry(src, dst)
    shutil.rmtree(bak, ignore_errors=True)
    os.rename(new, bak)
    os.replace(tmp, key)


def _label(scope: str, path: str) -> str:
    """Displayed name of an entry: `path` for the gitdir, `scope:path` otherwise."""
    return path if scope == "local" else f"{scope}:{path}"


def _copy_entry(src: Path, dst: Path) -> None:
    """Copy without ever following a link: a symlink is recreated as is."""
    if src.is_symlink():
        os.symlink(os.readlink(src), dst)
    else:
        shutil.copy2(src, dst, follow_symlinks=False)


def changes(old: dict, new: dict) -> list[tuple[str, tuple[str, str]]]:
    out = []
    for k in old.keys() - new.keys():
        out.append(("removed", k))
    for k in new.keys() - old.keys():
        out.append(("added", k))
    for k in old.keys() & new.keys():
        if (old[k].kind, old[k].mode, old[k].sha) != (new[k].kind, new[k].mode, new[k].sha):
            out.append(("modified", k))
    return sorted(out, key=lambda c: c[1])


def show_changes(repo: Repo, old: dict, new: dict, key: Path) -> None:
    colors = {"removed": STYLE.red, "added": STYLE.green, "modified": STYLE.yellow}
    for action, (scope, path) in changes(old, new):
        err("  " + colors[action](f"{action:<9} {san(_label(scope, path))}"))
    # Readable diff of the config: the gitdir's, and the main repository's
    # when in a linked worktree (that is the one git reads).
    for scope in ("local", "common") if repo.common != repo.gitdir else ("local",):
        old_cfg = Path(str(key) + ".d") / scope / "config"
        cfg = scope_base(repo, scope) / "config"
        if old_cfg.is_file() and cfg.is_file() and old_cfg.read_bytes() != cfg.read_bytes():
            err("\n  " + STYLE.bold(f"diff of {san(cfg)}:"))
            a = old_cfg.read_text(errors="replace").splitlines()
            b = cfg.read_text(errors="replace").splitlines()
            for line in list(difflib.unified_diff(a, b, lineterm=""))[2:]:   # without ---/+++
                color = (STYLE.green if line.startswith("+") else STYLE.red if line.startswith("-")
                         else STYLE.cyan if line.startswith("@@") else str)
                err("  " + color(san(line)))


# ------------------------------------------------------------------ restore
def restore(repo: Repo, key: Path, old: dict, new: dict, yes: bool,
            trusted_refs: list[tuple[str, Path]]) -> None:
    bak = Path(str(key) + ".d")
    if not bak.is_dir():
        raise Refuse(f"no backup for {repo.root} (run 'gitguard trust' again when the repository is clean)")
    plan = [(("delete" if a == "added" else "restore"), k)
            for a, k in changes(old, new) if k[0] != "global"]
    # A deletion may only target the inside of the gitdir or of a root that the
    # **trusted** config designated. Without this, an `ext:` path that appeared
    # after the trust (hooksPath turned into a symlink to $HOME, say) made
    # gitguard delete files outside the repository — found in review.
    allowed = [repo.gitdir, repo.common] + [p for _, p in trusted_refs]
    for action, (scope, path) in plan:
        if action != "delete":
            continue
        target = (scope_base(repo, scope) / path).resolve()
        if not any(a == target or a in target.parents for a in allowed):
            raise Refuse(f"{scope}:{path} is outside the paths designated by the trusted "
                         f"config: refusing to delete. Inspect the repository by hand.")
    if not plan:
        info(f"nothing to restore, {repo.root} is in the trusted state")
        return
    err(STYLE.bold(f"Actions on {san(repo.root)}:"))
    for action, (scope, path) in plan:
        color = STYLE.red if action == "delete" else STYLE.green
        err(f"  {color(action)} {san(_label(scope, path))}")
    if not yes:
        try:
            ans = input(STYLE.yellow("Continue? [y/N] "))
        except EOFError:
            ans = ""
        if ans.lower() not in ("y", "yes"):
            raise Refuse("aborted")
    for action, (scope, path) in plan:
        base = scope_base(repo, scope)
        dst = base / path
        # The canonical parent must be the expected directory: if a component
        # is a symlink, do not write (redirection to ~/.ssh, ~/.bashrc…).
        # Checked on the first existing ancestor BEFORE any mkdir: creating the
        # missing parents through a link would already write at the target.
        anc = dst.parent
        while not (anc.exists() or anc.is_symlink()):
            anc = anc.parent
        if anc.resolve() != base.resolve() / anc.relative_to(base):
            raise Refuse(f"non-canonical path (intermediate symlink): {dst} — repair by hand")
        dst.parent.mkdir(parents=True, exist_ok=True)
        if dst.parent.resolve() != (base.resolve() / path).parent:
            raise Refuse(f"non-canonical path (intermediate symlink): {dst} — repair by hand")
        if dst.is_symlink() or dst.exists():
            dst.unlink()
        if action == "restore":
            _copy_entry(bak / scope / path.lstrip("/"), dst)
    if manifest(repo, config_refs(repo)) == old:
        info(f"{len(plan)} file(s) restored, {repo.root} matches the trusted state again")
    else:
        warn("restore done, but the fingerprint still differs — check with 'gitguard diff'")


# --------------------------------------------------------- state management
def entries() -> Iterator[tuple[Path, Path | None, str]]:
    """(key, root, status) for each registered repository."""
    for key in sorted(STATE.glob("????????????????")):
        if not key.is_file():
            continue
        data = load_manifest(key)
        root_s = data.root if data else None
        if not root_s:
            rf = Path(str(key) + ".d") / ".root"
            root_s = rf.read_text().strip() if rf.is_file() else None
        root = Path(root_s) if root_s else None
        if root is None:
            yield key, None, "unknown"
            continue
        if not root.is_dir():
            yield key, root, "missing"
            continue
        try:
            repo = open_repo(root)
            refs = config_refs(repo)
            check_structure(repo, refs)
        except Refuse:
            yield key, root, "structure"
            continue
        if data is None or not data.current:
            yield key, root, "legacy"
        elif manifest(repo, refs) != data.entries:
            yield key, root, "modified"
        elif not (Path(str(key) + ".d")).is_dir():
            yield key, root, "legacy"
        else:
            yield key, root, "ok"


def cmd_list() -> None:
    colors = {"ok": STYLE.green, "modified": STYLE.red, "structure": STYLE.red,
              "missing": STYLE.yellow, "legacy": STYLE.yellow, "unknown": STYLE.yellow}
    n = 0
    for key, root, st in sorted(entries(), key=lambda t: str(t[1])):
        n += 1
        date = time.strftime("%Y-%m-%d %H:%M", time.localtime(key.stat().st_mtime))
        label = str(root) if root else f"<key {key.name}, trusted by an older version>"
        err(f"{colors[st](f'{st:<10}')} {date}  {san(label)}")
    if n == 0:
        info(f"no repository registered in {STATE}")
    check_safe_bare()


def forget_key(key: Path) -> None:
    # <key>.config: leftover of states written by the old bash script.
    for suffix in ("", ".config", ".tmp", ".idx", ".idx.tmp"):
        p = Path(str(key) + suffix)
        if p.exists():
            p.unlink()
    shutil.rmtree(str(key) + ".d", ignore_errors=True)
    shutil.rmtree(str(key) + ".d.tmp", ignore_errors=True)


def cmd_forget(args: list[str]) -> None:
    if not args:
        raise Refuse("usage: gitguard forget <repo>... | --missing")
    if args[0] == "--missing":
        n = 0
        for key, root, st in entries():
            if st in ("missing", "unknown"):
                forget_key(key)
                n += 1
                info(f"forgotten: {root or key.name}")
        if n == 0:
            info("nothing to clean up")
        return
    for a in args:
        root = Path(a).resolve()
        key = key_for(root)
        if not key.is_file():
            warn(f"not registered: {root}")
            continue
        forget_key(key)
        info(f"forgotten: {root}")


def cmd_retrust() -> None:
    n = skipped = 0
    for key, root, st in entries():
        if st in ("ok", "legacy") and root:
            save_trust(open_repo(root))
            n += 1
            info(f"re-trusted: {root}")
        else:
            skipped += 1
            warn(f"skipped ({st}): {root or key.name}")
    info(f"{n} repository(ies) re-trusted, {skipped} skipped")
    check_safe_bare()


# -------------------------------------------------------- exec mode (git …)
GLOBAL_WITH_ARG = {"-c", "--namespace", "--exec-path", "-C", "--git-dir", "--work-tree"}


@dataclass
class GlobalOpts:
    cwd: Path                 # effective cwd after the -C options (not canonicalised)
    gitdir: Path | None       # --git-dir, relative to that cwd
    worktree: Path | None     # --work-tree, relative to that cwd
    rest: list[str]           # from the subcommand onwards


def split_global_options(args: list[str], cwd: Path) -> GlobalOpts:
    """Interpret git's global options as git would, without side effects.
    `--work-tree` does **not** change gitdir discovery — git does it from the
    cwd (or GIT_DIR); moving there made gitguard check another repository
    while git executed the config of the cwd's repository [18]. It does
    however designate the tree to check when `--git-dir` is given [28]."""
    gitdir: Path | None = None
    worktree: Path | None = None
    i = 0
    while i < len(args):
        a = args[i]
        if a in GLOBAL_WITH_ARG and i + 1 >= len(args):
            raise Refuse(f"option {a} without an argument")
        if a == "-C":
            cwd = cwd / args[i + 1]; i += 2
        elif a.startswith("--git-dir="):
            gitdir = cwd / a[len("--git-dir="):]; i += 1
        elif a == "--git-dir":
            gitdir = cwd / args[i + 1]; i += 2
        elif a.startswith("--work-tree="):
            worktree = cwd / a[len("--work-tree="):]; i += 1
        elif a == "--work-tree":
            worktree = cwd / args[i + 1]; i += 2
        elif a in GLOBAL_WITH_ARG:
            i += 2                       # -c, --namespace, --exec-path
        elif a.startswith("-"):
            i += 1                       # --no-pager, -p, --bare…
        else:
            break
    return GlobalOpts(cwd, gitdir, worktree, args[i:])


def apply_global_options(args: list[str]) -> Path:
    """Move as git would to choose the repository to check (chdir for -C,
    GIT_DIR for --git-dir) and return the original cwd so git can be re-run
    from there afterwards with its options intact (no double cd)."""
    orig = Path.cwd()
    o = split_global_options(args, orig)
    try:
        os.chdir(o.cwd)
    except OSError as e:
        raise Refuse(f"-C {o.cwd}: {e.strerror}")
    if o.gitdir is not None:
        os.environ["GIT_DIR"] = str(o.gitdir.resolve())
    if o.worktree is not None:
        os.environ["GIT_WORK_TREE"] = str(o.worktree.resolve())
    return orig


CLONE_WITH_ARG = {"-o", "-b", "--branch", "--origin", "-u", "--upload-pack", "--reference",
                  "--depth", "--jobs", "-j", "--config", "--filter", "--shared",
                  "--object-format", "--initial-branch", "--ref-format", "--template"}


def _template_dir_configured() -> bool:
    """`init.templateDir` in the global/system config copies hooks into every
    new repository: like `--template=`, it rules out auto-trust."""
    for f in global_config_files():
        for section, key, _ in parse_git_config(f):
            if section == "init" and key == "templatedir":
                return True
    return False


def parse_new_repo(args: list[str]) -> tuple[str, Path] | None:
    """(clone|init, target directory) if the command creates a repository, else None."""
    o = split_global_options(args, Path.cwd())
    cwd = o.cwd.resolve()
    if not o.rest or o.rest[0] not in ("clone", "init"):
        return None
    sub, rest, positional, bare, template = o.rest[0], o.rest[1:], [], False, False
    j = 0
    while j < len(rest):
        a = rest[j]
        if a == "--":
            positional += rest[j + 1:]; break
        if a.startswith("--template"):
            template = True; j += 2 if a == "--template" else 1
        elif a in ("--bare", "--mirror"):
            bare = True; j += 1
        elif a.startswith("--separate-git-dir"):
            return None
        elif a in CLONE_WITH_ARG:
            j += 2
        elif a.startswith("-"):
            j += 1
        else:
            positional.append(a); j += 1
    if template or _template_dir_configured():
        warn("templateDir: no auto-trust, run 'gitguard trust' after inspection")
        return None
    if bare:
        return None
    if sub == "clone":
        if not positional:
            return None
        if len(positional) >= 2:
            d = positional[1]
        else:
            url = positional[0].rstrip("/")
            if url.endswith(".git"):
                url = url[:-4]
            d = url.rsplit("/", 1)[-1].rsplit(":", 1)[-1]
    else:
        d = positional[0] if positional else "."
    return sub, (cwd / d)


def run_git(args: list[str], orig: Path, newrepo: tuple[str, Path] | None) -> int:
    os.chdir(orig)
    if newrepo is None:
        os.execv(REAL_GIT, [REAL_GIT, *args])
    sub, d = newrepo
    preexisting = (d / ".git").exists() or (d / ".git").is_symlink()
    rc = subprocess.call([REAL_GIT, *args])
    if rc == 0:
        d = d.resolve()
        if preexisting:
            warn(f"{d} already contained a .git before '{sub}': no auto-trust (gitguard trust after inspection)")
        elif (d / ".git").is_dir():
            try:
                save_trust(open_repo(d))
                info(f"new repository trusted: {d}")
            except Refuse as e:
                warn(f"cannot trust {d} automatically: {e}")
    return rc


# ------------------------------------------------- auto-accept and prompt
_BRANCH_KEYS = {"remote", "merge"}
_REF_OK = re.compile(r"^refs/heads/[^\s]+$")


def branch_tracking_only(old_items: list[tuple[str, str, str]],
                         new_items: list[tuple[str, str, str]]) -> list[str]:
    """If the only semantic difference between two configs is the addition or
    removal of `branch.<x>.remote` / `branch.<x>.merge`, return the branches
    concerned; otherwise []. This is what `push -u`, `branch -u` and
    `checkout -b` (autoSetupMerge) write: neither key can make anything run.
    `remote` must name a remote already present in the trusted config (or
    `.`), `merge` a `refs/heads/…`. Closed list, not to be extended without
    proof: this is not a blocklist of dangerous keys but an allowlist of two
    harmless ones — the fingerprint remains the rule for everything else."""
    from collections import Counter
    old_c, new_c = Counter(old_items), Counter(new_items)
    delta = list((old_c - new_c).elements()) + list((new_c - old_c).elements())
    if not delta:
        return []                       # nothing semantic (a comment…): not for us
    remotes = {sec[len("remote."):] for sec, _, _ in old_items if sec.startswith("remote.")}
    branches: set[str] = set()
    for section, key, value in delta:
        if not section.startswith("branch.") or key not in _BRANCH_KEYS:
            return []
        name = section[len("branch."):]
        if not name or _CTRL.search(name) or "\n" in name:
            return []
        if key == "remote" and value != "." and value not in remotes:
            return []
        if key == "merge" and not _REF_OK.match(value):
            return []
        branches.add(name)
    return sorted(branches)


def auto_accept(repo: Repo, key: Path, old: Manifest, new: dict) -> list[str]:
    """The only change is `config` (of the gitdir, or of the main repository
    when in a linked worktree) and that `config` differs only by branch
    tracking: return the branches, the caller re-trusts. Otherwise []."""
    ch = changes(old.entries, new)
    if len(ch) != 1 or ch[0][0] != "modified" or ch[0][1][1] != "config":
        return []
    scope = ch[0][1][0]
    if scope not in ("local", "common"):
        return []
    old_cfg = Path(str(key) + ".d") / scope / "config"
    if not old_cfg.is_file():
        return []
    return branch_tracking_only(parse_git_config(old_cfg),
                                parse_git_config(scope_base(repo, scope) / "config"))


def ask_on_tty(question: str) -> bool:
    """Ask the question on /dev/tty — never on stdin, which git will consume
    (`git apply < patch`, `commit -F -`, `update-index --stdin`). False when
    there is no terminal (script, IDE, cron), when stderr is not a terminal
    (the diff just shown was not seen) or when GITGUARD_NO_PROMPT is set."""
    if os.environ.get("GITGUARD_NO_PROMPT") or not sys.stderr.isatty():
        return False
    try:
        # Two opens: "r+" in text mode requires a seekable stream.
        with open("/dev/tty", "w") as out, open("/dev/tty") as inp:
            out.write(san(question))
            out.flush()
            ans = inp.readline()
    except OSError:
        return False
    return ans.strip().lower() in ("y", "yes")


# --------------------------------------------------------------------- main
def check_or_die(repo: Repo, key: Path, old: Manifest | None, new: dict,
                 refs: list[tuple[str, Path]], interactive: bool = False) -> None:
    """Refuse if the repository is not in the trusted state. In exec mode
    (`interactive`), two shortcuts before refusing: auto-accept of a pure
    branch-tracking addition, then a question on the terminal, diff shown,
    default answer N. Never for "never trusted" (nothing to show: that would
    bless an unknown state) nor for a structural refusal (raised earlier, in
    check_structure)."""
    if old is None or not old.current:
        rule()
        why = "trusted by an older version" if old else "never trusted"
        raise Refuse(f"repository {why}: {repo.root}\n  Inspect .git/config and .git/hooks, then:  "
                     + STYLE.cyan("gitguard trust"))
    if old.entries == new:
        return
    if interactive:
        branches = auto_accept(repo, key, old, new)
        if branches:
            save_trust(repo, refs, new)
            info(f"config: branch tracking for {', '.join(san(b) for b in branches)} "
                 f"→ reference updated")
            return
    rule()
    warn(STYLE.bold(f"{repo.root}/.git has changed since the last trust"))
    show_changes(repo, old.entries, new, key)
    err("")
    rule()
    if interactive and ask_on_tty(STYLE.yellow(
            "Trust this state and run git? [y/N] ")):
        save_trust(repo, refs, new)
        info(f"trust state recorded for {repo.root}")
        return
    hint("If legitimate:  gitguard trust      Otherwise:  gitguard restore")
    raise Refuse("refusing to run git.")


def main(argv: list[str]) -> int:
    mode, yes = "check", False
    if Path(argv[0]).name == "git":
        mode, argv = "exec", argv[1:]    # invoked through a symlink named git
    else:
        argv = argv[1:]
        cmd = argv[0] if argv else ""
        if cmd in ("trust", "diff"):
            mode, argv = cmd, argv[1:]
        elif cmd == "restore":
            mode, argv = "restore", argv[1:]
            if argv and argv[0] == "-y":
                yes, argv = True, argv[1:]
        elif cmd == "git":
            mode, argv = "exec", argv[1:]
        elif cmd == "list":
            cmd_list(); return 0
        elif cmd == "forget":
            cmd_forget(argv[1:]); return 0
        elif cmd == "prune":
            cmd_forget(["--missing"]); return 0
        elif cmd == "retrust":
            cmd_retrust(); return 0
        elif cmd in ("help", "-h", "--help"):
            print(__doc__); return 0

    orig = Path.cwd()
    newrepo = None
    if mode == "exec":
        newrepo = parse_new_repo(argv)
        orig = apply_global_options(argv)

    root = find_root(Path.cwd())
    if root is None:
        if mode == "exec":
            return run_git(argv, orig, newrepo)
        if mode != "check":
            raise Refuse(f"no git repository here: {Path.cwd()}")      # [30]
        return 0
    repo = open_repo(root)
    refs = config_refs(repo)
    check_structure(repo, refs)
    key = repo.key
    new = manifest(repo, refs)
    old = load_manifest(key)

    if mode == "trust":
        save_trust(repo, refs, new)
        info(f"trust state recorded for {repo.root}")
        wt = [f"{s}:{p}" for s, p in refs]
        if wt:
            hint(f"the config references outside the gitdir: {' '.join(wt)} → watched too")
        check_safe_bare()
        return 0
    if mode == "diff":
        if old is None:
            raise Refuse(f"no trust state for {repo.root} (gitguard trust)")
        if old.entries == new:
            info(f"no changes in {repo.root}")
        else:
            warn(f"changes in {repo.root}/.git:")
            show_changes(repo, old.entries, new, key)
        return 0
    if mode == "restore":
        if old is None:
            raise Refuse(f"no trust state for {repo.root} (gitguard trust)")
        restore(repo, key, old.entries, new, yes, old.refs)
        return 0

    check_or_die(repo, key, old, new, refs, interactive=(mode == "exec"))
    if mode == "exec":
        return run_git(argv, orig, newrepo)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except Refuse as e:
        fail(str(e))
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as e:               # noqa: BLE001 — never a raw traceback
        # Fail closed: git is not run. The message is sanitized like everything
        # else; the full traceback only on request.
        if os.environ.get("GITGUARD_DEBUG"):
            raise
        fail(f"internal error ({type(e).__name__}): {e}")
        hint("retry with GITGUARD_DEBUG=1 for the full traceback")
        sys.exit(1)
