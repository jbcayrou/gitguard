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
  gitguard pending [<repo>... | -a | -c <repo>...]
                         decisions waiting: a git run by a program with no
                         terminal (editor, build, cron) blocks until you allow
                         the shown state here, refuse it, or GITGUARD_WAIT ends
  gitguard forget <repo>... | --missing
  gitguard prune         = forget --missing
  gitguard retrust       re-validate unchanged repositories (after an upgrade)
  gitguard help

Alias:    alias git='gitguard git'      Wrapper: ln -s ~/bin/gitguard ~/bin/git
System:   /usr/bin/git → gitguard, the real git diverted to /usr/bin/git.real
          (dpkg-divert); a `git.real` next to gitguard is used before the PATH
Env:      GITGUARD_STATE, GITGUARD_REAL_GIT, GITGUARD_ALLOW_REBASE_EXEC,
          GITGUARD_NO_PROMPT, GITGUARD_WAIT (seconds a terminal-less git waits
          for `gitguard pending`, 0 = never, default 60), GITGUARD_NO_NOTIFY,
          GITGUARD_DEBUG, NO_COLOR

Threat model, design choices and vulnerability history: see CLAUDE.md.
"""
from __future__ import annotations

import difflib
import fcntl
import hashlib
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import termios
import time
from dataclasses import dataclass, field
from functools import cached_property
from pathlib import Path
from typing import Iterator

FORMAT_VERSION = 4   # 4: symlink hashes include the target's content


def real_git() -> str:
    """The git to run: `GITGUARD_REAL_GIT`; else a `git.real` next to the path
    gitguard was invoked by (system-wide install: `/usr/bin/git` → gitguard,
    the real git diverted to `/usr/bin/git.real`; an environment variable
    would not reach cron, systemd or a GUI); else the first `git` of the PATH
    that is not gitguard itself (the `~/bin/git` symlink deployment puts
    gitguard ahead of it). The sibling wins over the PATH on purpose: when
    `/usr/bin/git` was diverted, the git the user would have run is
    `/usr/bin/git.real`, not another one elsewhere in the PATH. The former
    default `/usr/bin/git` silently ran another git than the user's (Apple's
    instead of Homebrew's on a Mac), with another system config."""
    if os.environ.get("GITGUARD_REAL_GIT"):
        return os.environ["GITGUARD_REAL_GIT"]
    me = Path(__file__).resolve()

    def usable(cand: Path) -> bool:
        try:
            return cand.is_file() and os.access(cand, os.X_OK) and cand.resolve() != me
        except OSError:
            return False

    # With a shebang script the kernel passes the path it found in the PATH
    # (`/usr/bin/git`), so argv[0] names the invoked link; __file__ resolved
    # names the real file (`/usr/bin/gitguard`). A bare argv[0] (`python3
    # gitguard.py`) has no directory: never the cwd, which may be the volume.
    invoked = Path(sys.argv[0]).parent
    for d in dict.fromkeys([invoked, me.parent] if invoked != Path() else [me.parent]):
        cand = d / "git.real"
        if usable(cand):
            return str(cand)
    for d in os.environ.get("PATH", os.defpath).split(os.pathsep):
        cand = Path(d or ".") / "git"
        if usable(cand):
            return str(cand)
    raise Refuse("no git found: none in the PATH other than gitguard itself, no `git.real` "
                 "next to gitguard — set GITGUARD_REAL_GIT")
STATE = Path(os.environ.get("GITGUARD_STATE") or Path.home() / ".local/state/gitguard")
WAIT_DEFAULT = 60.0      # seconds a git without a controlling terminal waits for `gitguard pending`
WAIT_POLL = 0.5
NOTIFY_COOLDOWN = 600    # one desktop notification per repository per 10 minutes
NOTIFY_SEND = "/usr/bin/notify-send"     # absolute: a PATH entry may live in the volume
OSASCRIPT = "/usr/bin/osascript"
INCLUDE_DEPTH = 10      # git: MAX_INCLUDE_DEPTH = 10
# No walk of the work tree looking for nested `.git`: git opens a nested
# repository only once a gitlink references it in the index, which is read
# at every command (`index_gitlinks`), and the `git add -A` that creates the
# gitlink executes nothing by itself (tests/nested_git_is_a_threat.sh,
# test_first_add_does_not_execute). The command that FOLLOWS the `add` is
# refused. A walk (`GITGUARD_SCAN_TREE`, removed 2026-10-18) only closed the
# window between that `add` and the next wrapped command — a window only a
# git outside the wrapper can exploit, which is out of scope by design — for
# +0.2 s per command on the Linux kernel. See CLAUDE.md, "Nested repositories".

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
        self.recorded = False      # a pending record was already written for it


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
# Where gitguard's own output goes. stderr by default: in exec mode stdout
# belongs to git, and a refusal is a diagnostic. The management commands
# (trust, diff, restore, list, forget, prune, retrust) switch it to stdout,
# so that `gitguard list | grep` works; warnings and errors stay on stderr.
OUT = sys.stderr


def set_output(stream) -> None:
    global OUT
    OUT = stream
    STYLE.enabled = stream.isatty() and not os.environ.get("NO_COLOR")
_CTRL = re.compile(r"[\x00-\x09\x0b-\x1f\x7f]")   # everything but \n (handled separately)
# Only the SGR codes Style emits (reset, bold, red/green/yellow/cyan). Any
# other SGR is neutralized: conceal (8), fg = bg (30;40, 38;5;n;48;5;n)…
# hid the rest of a config line in the diff shown before [y/N]. [43]
_SGR = re.compile(r"\x1b\[(?:0|1|3[1236])?m")


def san(s: object) -> str:
    """Neutralize control characters in text about to be displayed.

    The SGR sequences gitguard itself emits (reset, bold, four foreground
    colours) are kept: they can neither clear the screen, nor move the cursor,
    nor hide text — an attacker who colours a file name gains nothing. Any
    other SGR (conceal, background colours, 256/true colour) is neutralized:
    it could make the rest of a line invisible. [43] Any other control character (lone ESC, erase
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
    """Write an already composed message (sanitized data, colours included)
    to the current output (see OUT)."""
    print(msg, file=OUT)


def _tag(color, mark: str, msg: str, stream=None) -> None:
    print(f"{color(STYLE.bold(mark + ' gitguard:'))} {san(msg)}", file=stream or OUT)


def info(msg: str) -> None:
    _tag(STYLE.green, "✓", msg)


def warn(msg: str) -> None:
    _tag(STYLE.yellow, "!", msg, sys.stderr)


def fail(msg: str) -> None:
    _tag(STYLE.red, "✗", msg, sys.stderr)


def hint(msg: str) -> None:
    err(f"  {STYLE.cyan(san(msg))}")


def rule() -> None:
    err(STYLE.red("─" * 56))


# ------------------------------------------------------------ config parser
# A character-by-character port of git's config.c (git_parse_source,
# get_base_var, get_extended_base_var, get_value, parse_value), so that what
# gitguard reads is what git reads. The previous regex-and-split parser
# diverged on a UTF-8 BOM, a `\` ending a comment line, a `\` at EOF,
# internal whitespace (kept as is by git) and on the characters git's isspace
# does not know (\v, \f, NBSP): each one hid a `core.hooksPath`. [46]
_GIT_SPACE = " \t\r\n"          # git's isspace (sane_ctype), NOT str.isspace


class _Src:
    """get_next_char: `\\r\\n` reads as `\\n`; at EOF a `\\n` is returned and
    `eof` set, as git does."""
    __slots__ = ("text", "i", "eof", "line")

    def __init__(self, text: str) -> None:
        self.text, self.i, self.eof, self.line = text, 0, False, 1

    def get(self) -> str:
        if self.i >= len(self.text):
            self.eof = True
            return "\n"
        c = self.text[self.i]
        self.i += 1
        if c == "\r" and self.i < len(self.text) and self.text[self.i] == "\n":
            self.i += 1
            c = "\n"
        if c == "\n":
            self.line += 1
        return c


def _iskeychar(c: str) -> bool:
    return c.isascii() and (c.isalnum() or c == "-")


def _parse_value(src: _Src) -> str | None:
    """parse_value. None where git dies (bad escape, unterminated quote).
    Leading whitespace skipped, trailing whitespace trimmed, internal
    whitespace kept as is; `#`/`;` outside quotes start a comment; `\\` + newline
    continues the value — inside a comment nothing is special any more."""
    out: list[str] = []
    quote = comment = False
    trim = -1                       # length before the trailing whitespace
    while True:
        c = src.get()
        if c == "\n":
            if quote:
                return None
            if trim >= 0:
                del out[trim:]
            return "".join(out)
        if comment:
            continue
        if c in _GIT_SPACE and not quote:
            if trim < 0:
                trim = len(out)
            if out:
                out.append(c)
            continue
        if not quote and c in "#;":
            comment = True
            continue
        trim = -1
        if c == "\\":
            c = src.get()
            if c == "\n":
                continue
            if c in "tbn":
                c = {"t": "\t", "b": "\b", "n": "\n"}[c]
            elif c not in "\\\"":
                return None
            out.append(c)
            continue
        if c == '"':
            quote = not quote
            continue
        out.append(c)


def _parse_section(src: _Src) -> str | None:
    """get_base_var / get_extended_base_var, after the `[`: `base` (lower-cased,
    `.` allowed) or `base "subsection"` (kept as is, `\\x` is `x`). None where
    git dies."""
    name: list[str] = []
    while True:
        c = src.get()
        if src.eof:
            return None
        if c == "]":
            break
        if c in _GIT_SPACE:
            while c in _GIT_SPACE:
                if c == "\n":
                    return None
                c = src.get()
            if c != '"':
                return None
            name.append(".")
            while True:
                c = src.get()
                if c == "\n":
                    return None
                if c == '"':
                    break
                if c == "\\":
                    c = src.get()
                    if c == "\n":
                        return None
                name.append(c)
            if src.get() != "]":
                return None
            break
        if not (_iskeychar(c) or c == "."):
            return None
        name.append(c.lower())
    return "".join(name) or None


def _parse_config_text(text: str, where: str) -> list[tuple[str, str, str]]:
    """git_parse_source. A line git rejects makes git die before running
    anything: gitguard refuses too, rather than guess what follows."""
    out: list[tuple[str, str, str]] = []
    if text.startswith("﻿"):          # UTF-8 BOM, only at the very start
        text = text[1:]
    src = _Src(text)
    section = ""
    comment = False
    while True:
        c = src.get()
        if c == "\n":
            if src.eof:
                return out
            comment = False
            continue
        if comment or c in _GIT_SPACE:
            continue
        if c in "#;":
            comment = True
            continue
        if c == "[":
            sec = _parse_section(src)
            if sec is None:
                break
            section = sec
            continue
        if not (c.isascii() and c.isalpha()):
            break
        key = [c.lower()]
        while True:
            c = src.get()
            if src.eof or not _iskeychar(c):
                break
            key.append(c.lower())
        while c in " \t":
            c = src.get()
        if c == "\n":
            value = "true"
        elif c == "=":
            v = _parse_value(src)
            if v is None:
                break
            value = v
        else:
            break
        out.append((section, "".join(key), value))
    raise Refuse(f"{where}: bad config line {src.line - (1 if src.eof else 0)} (git refuses it too)")


def parse_git_config(path: Path) -> list[tuple[str, str, str]]:
    """Return [(section, key, value)], section lower-cased with its subsection
    ("includeIf.gitdir:x"), key lower-cased, exactly as git reads them. Never
    via `git config`: git would honour the very config we are trying to judge.
    A NUL byte makes git truncate the value (C string): refused instead, a
    config is never meant to contain one."""
    try:
        text = path.read_text(errors="surrogateescape")
    except OSError:
        return []
    if "\0" in text:
        raise Refuse(f"{path}: NUL byte in a config file")
    return _parse_config_text(text, str(path))


def _unquote(raw: str) -> str:
    """A config value as git would read the text after `=`."""
    v = _parse_value(_Src(raw))
    if v is None:
        raise ValueError(f"bad config value {raw!r}")
    return v


# ---------------------------------------------------------- repo / gitdir
def key_for(root: Path) -> Path:
    """State key of a repository: first 16 hex digits of the sha256 of its canonical root."""
    return STATE / hashlib.sha256(str(root).encode()).hexdigest()[:16]


@dataclass
class Repo:
    root: Path        # work tree root, canonical (core.worktree honoured)
    gitdir: Path      # real gitdir (resolved if gitfile)
    common: Path      # commondir (== gitdir outside a linked worktree)
    # Directory whose `.git` was discovered: the state key and `.root` are
    # derived from it, not from a `core.worktree` the config may redirect
    # the tree to (that redirection is itself a config change). [47]
    anchor: Path | None = None

    @property
    def key(self) -> Path:
        return key_for(self.anchor or self.root)

    @property
    def label(self) -> Path:
        """How the repository is named to the user: the directory holding `.git`."""
        return self.anchor or self.root

    @cached_property
    def gitfiles(self) -> list[Path]:
        """Every nested `.git` to check: those declared in `.gitmodules` and
        those referenced by an index gitlink, wherever they are
        (`node_modules/pkg` included). [6] [14] [24]"""
        out = set(gitmodules_gits(self.root))
        for rel in index_gitlinks(self.gitdir, Path(str(self.key) + ".idx")):
            g = self.root / rel / ".git"
            if g.exists() or g.is_symlink():
                out.add(g)
        return sorted(out)


def _validate_headref(p: Path) -> bool:
    """git's validate_headref: a symlink to `refs/…`, or a file holding
    `ref: refs/…` (any git whitespace after the colon) or a hex object id."""
    try:
        st = p.lstat()
    except OSError:
        return False
    if stat.S_ISLNK(st.st_mode):
        return os.readlink(p).startswith("refs/")
    try:
        with open(p, "rb") as fh:
            buf = fh.read(255).split(b"\0", 1)[0]
    except OSError:
        return False
    if buf.startswith(b"ref:") and buf[4:].lstrip(b" \t\r\n").startswith(b"refs/"):
        return True
    return re.match(rb"[0-9a-fA-F]{40}", buf) is not None


def is_bare_gitdir(d: Path) -> bool:
    """git's is_git_directory, the test behind its discovery: a valid HEAD,
    then `objects` and `refs` reachable (access X_OK) in the common dir — the
    directory itself, or what its `commondir` file names. This is how git
    recognises a bare repository, or any directory a container has stuffed
    with these names. The former "HEAD file + objects/ + refs/ here" missed a
    `HEAD` symlink and a `commondir` redirection git accepts. [49]"""
    if not _validate_headref(d / "HEAD"):
        return False
    common = d
    cd = d / "commondir"
    if cd.is_file():
        try:
            common = d / cd.read_text(errors="surrogateescape").rstrip("\r\n")
        except OSError:
            return False
    objects = Path(os.environ["GIT_OBJECT_DIRECTORY"]) if os.environ.get("GIT_OBJECT_DIRECTORY") \
        else common / "objects"
    return os.access(objects, os.X_OK) and os.access(common / "refs", os.X_OK)


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
        g = d / ".git"
        if g.is_symlink() or g.is_file():
            return d                  # gitfile (a symlink is refused by open_repo)
        if g.is_dir():
            # A `.git` directory that is not a repository for git (no valid
            # HEAD, objects or refs) is skipped by git, which keeps walking
            # up; stopping on it checked — and let the user trust — a bogus
            # gitdir while git used the parent's. [49]
            if is_bare_gitdir(g):
                return d
        elif g.exists():
            return d                  # neither file nor directory: refused later
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
    anchor = root
    if not os.environ.get("GIT_DIR"):
        # core.worktree: git takes that directory as the work tree (relative
        # to the gitdir) and resolves a relative core.hooksPath there; the
        # directory containing `.git` was kept, and the hooks never watched.
        # Read where git reads it: the common config, then config.worktree
        # if extensions.worktreeConfig is set. [47]
        wt, ext = None, False
        for section, key, value in parse_git_config(common / "config"):
            if section == "core" and key == "worktree":
                wt = value
            elif section == "extensions" and key == "worktreeconfig":
                ext = value.lower() in ("true", "yes", "on", "1")
        if ext:
            for section, key, value in parse_git_config(g / "config.worktree"):
                if section == "core" and key == "worktree":
                    wt = value
        if wt:
            root = _expand2(wt, g)[1]
    return Repo(root, g.resolve(), common, anchor)


# ------------------------------------------------------- structural checks
def gitmodules_paths(root: Path) -> list[str]:
    return [v for s, k, v in parse_git_config(root / ".gitmodules")
            if s.startswith("submodule.") and k == "path"]


def gitmodules_gits(root: Path) -> list[Path]:
    """The `.git` of every path declared in `.gitmodules`: git will descend
    there, wherever it is. Read without any walk of the tree. [6]"""
    found: set[Path] = set()
    for rel in gitmodules_paths(root):
        p = root / rel / ".git"
        if p.exists() or p.is_symlink():
            found.add(p)
    return sorted(found)


def index_gitlinks(gitdir: Path, cache: Path | None = None) -> list[str]:
    """Paths recorded as gitlinks (mode 160000) in `.git/index`, read by
    parsing the file — never via `git`, which would read the config we judge.

    This is the criterion that matters: a nested repository is only dangerous
    once a gitlink references it, and the gitlink names it wherever it is.

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
    d = n.parent
    return (f"nested repository: {n} — a gitlink for this directory exists in the index "
            f"(a plain `git add -A` creates one), git will execute its config. If it is "
            f"your own vendored repository: inspect {n}/config and {n}/hooks, declare it "
            f"in .gitmodules and run `git submodule absorbgitdirs` (its gitdir moves under "
            f".git/modules/), then `gitguard trust`. Otherwise delete {n} first, then "
            f"`git rm --cached {d.name}`.")


def gitdir_roots(base: Path) -> Iterator[Path]:
    """`base`, then every gitdir root nested under `modules/` or `worktrees/`
    (a submodule name may contain `/`; a submodule has its own `modules/`).
    Recognised like _child_root (HEAD or commondir). Lists only those two
    directories, never a root's objects/: a handful of iterdir calls."""
    yield base
    stack = [base / "modules", base / "worktrees"]
    while stack:
        d = stack.pop()
        try:
            children = [c for c in d.iterdir() if c.is_dir() and not c.is_symlink()]
        except (FileNotFoundError, NotADirectoryError):
            continue
        except OSError as e:
            raise Refuse(f"unreadable directory {d}: {e.strerror}")
        for c in children:
            if (c / "HEAD").exists() or (c / "commondir").exists():
                yield from gitdir_roots(c)
            else:
                stack.append(c)


def check_rebase_todo(repo: Repo) -> None:
    """Rebase/cherry-pick todo lists live in volatile directories (git rewrites
    them at every step, so they cannot be part of the fingerprint) but accept
    `exec <cmd>` lines that git runs verbatim. The container can inject some
    during an in-progress rebase: refuse their presence, unless the user runs
    `--exec` rebases themselves. Also in submodules and linked worktrees:
    `submodule foreach 'git rebase --continue'` runs an unwrapped git. [36]"""
    if os.environ.get("GITGUARD_ALLOW_REBASE_EXEC"):
        return
    roots = dict.fromkeys([*gitdir_roots(repo.gitdir), *gitdir_roots(repo.common)])
    for p in (r / rel for r in roots for rel in TODO_FILES):
        if not p.is_file():
            continue
        for line in p.read_text(errors="surrogateescape").splitlines():
            # git accepts any blank after the command word (`exec<TAB>cmd`). [35]
            word = (line.split(None, 1) or [""])[0]
            if word in ("exec", "x"):
                raise Refuse(
                    f"`exec` line in {p}: git would run it on the next "
                    f"`rebase --continue`. Check this file; if this rebase is really "
                    f"yours, retry with GITGUARD_ALLOW_REBASE_EXEC=1.")


def check_structure(repo: Repo, refs: list[tuple[str, Path]]) -> None:
    check_split_index(repo)
    # Every nested .git — declared in .gitmodules or referenced by an index
    # gitlink, wherever it is (node_modules/, build/…) — must be
    # a file pointing under .git/modules (submodule) or under .git/worktrees
    # (linked worktree stored inside the tree, e.g. `.worktrees/x`).
    for n in repo.gitfiles:
        if n.is_symlink():
            raise Refuse(f"nested .git is a symlink: {n}")
        if n.is_dir():
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


CLI_CONFIG: list[str] = []       # `-c key=value` of the git command being run (exec mode)
CLI_CONFIG_ENV: list[str] = []   # `--config-env key=VAR` of that command


def _sq_dequote_step(s: str, i: int) -> tuple[str, int] | None:
    """git's sq_dequote_step: the single-quoted word starting at s[i] and the
    index just after it; the sequences `'\\''` and `'\\!'` inside the word stand
    for the quoted character. None if the text is not a quoted word."""
    if i >= len(s) or s[i] != "'":
        return None
    out: list[str] = []
    i += 1
    while True:
        if i >= len(s):
            return None
        c = s[i]
        i += 1
        if c != "'":
            out.append(c)
            continue
        if i + 2 < len(s) and s[i] == "\\" and s[i + 1] in "'!" and s[i + 2] == "'":
            out.append(s[i + 1])
            i += 3
            continue
        return "".join(out), i


def _parse_config_env_list(env: str) -> list[tuple[str, str | None]]:
    """GIT_CONFIG_PARAMETERS as git's parse_config_env_list reads it: words
    `'key'='value'`, `'key'=` (no value: boolean true) or the old style
    `'key=value'`, separated by whitespace. Refuse what git would die on."""
    out: list[tuple[str, str | None]] = []
    i = 0
    while True:
        while i < len(env) and env[i] in _GIT_SPACE:
            i += 1
        if i >= len(env):
            return out
        r = _sq_dequote_step(env, i)
        if r is None:
            raise Refuse("bogus format in GIT_CONFIG_PARAMETERS")
        key, i = r
        if i >= len(env) or env[i] in _GIT_SPACE:
            k, eq, v = key.partition("=")
            out.append((k, v if eq else None))
        elif env[i] == "=":
            i += 1
            if i < len(env) and env[i] == "'":
                r = _sq_dequote_step(env, i)
                if r is None or (r[1] < len(env) and env[r[1]] not in _GIT_SPACE):
                    raise Refuse("bogus format in GIT_CONFIG_PARAMETERS")
                out.append((key, r[0]))
                i = r[1]
            elif i >= len(env) or env[i] in _GIT_SPACE:
                out.append((key, None))
            else:
                raise Refuse("bogus format in GIT_CONFIG_PARAMETERS")
        else:
            raise Refuse("bogus format in GIT_CONFIG_PARAMETERS")


def _split_config_key(k: str) -> tuple[str, str] | None:
    """git_config_parse_key: `section[.subsection].key` → (section lower-cased
    with the subsection kept as is, key lower-cased); None if no dot."""
    if "." not in k:
        return None
    section, _, key = k.rpartition(".")
    head, dot, sub = section.partition(".")
    return head.lower() + (dot + sub if dot else ""), key.lower()


def env_config() -> list[tuple[str, str, str]]:
    """Config git takes from its environment and command line, in git's order
    (git_config_from_parameters): GIT_CONFIG_PARAMETERS — which a parent git
    feeds from its own `-c` — and this command's `-c` / `--config-env` (git
    appends them to it), then GIT_CONFIG_COUNT/GIT_CONFIG_KEY_n/VALUE_n. The
    sandbox cannot write any of it, but a value may name a path in the
    volume (`core.hooksPath`, `include.path`): git honours it. [48]"""
    pairs = _parse_config_env_list(os.environ.get("GIT_CONFIG_PARAMETERS", ""))
    for c in CLI_CONFIG:
        k, eq, v = c.partition("=")
        pairs.append((k, v if eq else None))
    for spec in CLI_CONFIG_ENV:
        k, eq, var = spec.rpartition("=")
        if not eq or var not in os.environ:
            raise Refuse(f"--config-env {spec!r}: missing '=' or environment variable (git refuses it too)")
        pairs.append((k, os.environ[var]))
    count = os.environ.get("GIT_CONFIG_COUNT")
    if count is not None:
        try:
            n = int(count)
        except ValueError:
            raise Refuse(f"bogus GIT_CONFIG_COUNT {count!r} (git refuses it too)")
        for i in range(n):
            k, v = os.environ.get(f"GIT_CONFIG_KEY_{i}"), os.environ.get(f"GIT_CONFIG_VALUE_{i}")
            if k is None or v is None:
                raise Refuse(f"GIT_CONFIG_COUNT={n} but GIT_CONFIG_KEY_{i}/VALUE_{i} missing (git refuses it too)")
            pairs.append((k, v))
    out = []
    for k, v in pairs:
        sk = _split_config_key(k)
        if sk is not None:
            out.append((*sk, "true" if v is None else v))
    return out


def global_config_files() -> list[Path]:
    """System and global config files git may read. Deliberately broad
    (GIT_CONFIG_GLOBAL *and* ~/.gitconfig *and* XDG): watching one file too
    many costs nothing, missing one is a bypass [16]."""
    out = [Path(os.environ.get("GIT_CONFIG_SYSTEM") or "/etc/gitconfig")]
    # A git built with another sysconfdir (Homebrew: /opt/homebrew/etc/gitconfig)
    # keeps its system config next to its prefix: <prefix>/bin/git → <prefix>/etc.
    # Derived from the path, never asked to git; one file too many costs nothing.
    if not os.environ.get("GIT_CONFIG_SYSTEM"):
        try:
            g = Path(real_git())
            for p in {g, g.resolve()}:
                if p.parent.name == "bin":
                    out.append(p.parent.parent / "etc/gitconfig")
        except Refuse:
            pass
    out.append(Path.home() / ".gitconfig")
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
        elif _replaceable(p):
            out[p] = "ext"

    # .lfsconfig: git-lfs reads lfs.customtransfer.*.path from it (a program it runs). [34]
    for special in [repo.label / ".git", repo.root / ".gitmodules",
                    repo.root / ".lfsconfig"]:
        if special.is_file():
            out[special] = "wt"
    for n in repo.gitfiles:
        if n.is_file():
            out[n] = "wt"

    # Config files git will read: local, the main repository's (a linked
    # worktree has no `config` of its own and uses commondir/config), then
    # system and global — their values also name paths the container can
    # write (global core.hooksPath, global include.path…).
    # Each config file comes with the directory its relative values are
    # resolved against: the root, or the submodule's own tree for the config
    # of `.git/modules/<x>` (hashed by walk_gitdir, but its hooksPath and
    # alias scripts live in the submodule's tree and were never watched). [39]
    # Third element: follow `remote.*.url`. Not for the config of a remote
    # itself — pushing to A does not push to A's remotes.
    queue = [(f, repo.root, True) for f in (repo.gitdir / "config", repo.gitdir / "config.worktree",
                                            repo.common / "config", repo.common / "config.worktree",
                                            *global_config_files())]
    queue += [(f, b, True) for f, b in _submodule_configs(repo)]
    seen: set[Path] = set()
    nxt: list[tuple[Path, Path, bool]] = []

    def consider(section: str, key: str, value: str, base: Path, cfdir: Path | None,
                 remotes: bool) -> None:
        if (section, key) in DIR_KEYS:
            add(*_expand2(value, base), allow_dir=True)
        elif section.startswith("include") and key == "path":
            # Relative to the including file; from the command line or the
            # environment git only accepts an absolute path ("relative config
            # includes must come from files").
            if cfdir is None and not _expand2(value, Path("/"))[0].is_absolute():
                return
            literal, p = _expand2(value, cfdir or base)
            if p.is_file():
                nxt.append((p, base, remotes))
            add(literal, p)
        elif remotes and section.startswith("remote.") and key in ("url", "pushurl"):
            # A local remote: `push` runs its hooks and honours its
            # config (hooksPath…). Only those, never the whole
            # directory ([25]): its config and its hooks/. [45]
            r = _local_remote(value, base)
            if r is not None:
                gd, rbase = r
                add(gd / "config", gd / "config")
                add(gd / "hooks", gd / "hooks", allow_dir=True)
                nxt.append((gd / "config", rbase, False))
        else:
            for tok in _value_tokens(value):
                if tok and tok not in (".", "..") and not tok.startswith("-"):
                    add(*_expand2(tok, base))

    # Config git takes from its environment and command line (GIT_CONFIG_*,
    # `-c`): not writable by the sandbox, but its values may name paths in
    # the volume, which git honours like any other. [48]
    for section, key, value in env_config():
        consider(section, key, value, repo.root, None, True)
    # +1: the first round consumes the base files; git then follows
    # INCLUDE_DEPTH levels of includes. With range(INCLUDE_DEPTH) the 10th
    # level was hashed but never parsed. [17]
    for _ in range(INCLUDE_DEPTH + 1):
        for cf, base, remotes in queue:
            if cf in seen or not cf.is_file():
                continue
            seen.add(cf)
            for section, key, value in parse_git_config(cf):
                consider(section, key, value, base, cf.parent, remotes)
        queue, nxt = nxt, []
    return sorted(((scope, p) for p, scope in out.items()), key=lambda t: str(t[1]))


def _replaceable(p: Path) -> bool:
    """Can the user — hence a container running as the user on a mounted
    volume — rewrite `p` or replace it? A 0555 script in a writable directory
    is unlinked and recreated: testing the file alone ignored it. [38]
    (Cost: a read-only file under a user-owned tree, e.g. a Homebrew binary
    named by absolute path in gpg.program, is now hashed: ~1 ms per MB.)"""
    return os.access(p, os.W_OK) or any(os.access(q, os.W_OK) for q in p.parents)


def _local_remote(url: str, base: Path) -> tuple[Path, Path] | None:
    """(gitdir, base for its relative values) if the remote URL designates a
    local repository (path or file://), else None. Like git: a `host:path`
    without a `/` before the colon is ssh; `<path>.git` is tried too."""
    v = url[len("file://"):] if url.startswith("file://") else url
    if "://" in v or (":" in v.split("/", 1)[0] and not v.startswith(("/", ".", "~"))):
        return None
    p = _expand2(v, base)[1]
    for cand in (p, p.with_name(p.name + ".git")):
        if (cand / ".git").is_dir():
            return cand / ".git", cand
        if is_bare_gitdir(cand):
            return cand, cand
    return None


def _submodule_configs(repo: Repo) -> list[tuple[Path, Path]]:
    """(config file, submodule tree) for every nested gitdir that has a
    `core.worktree` (submodules; a linked worktree's gitdir has none and is
    checked when git runs there). A few small files: no measurable cost."""
    out = []
    for r in dict.fromkeys([*gitdir_roots(repo.gitdir), *gitdir_roots(repo.common)]):
        if r in (repo.gitdir, repo.common) or not (r / "config").is_file():
            continue
        wt = None
        for section, key, value in parse_git_config(r / "config"):
            if section == "core" and key == "worktree":
                wt = value
        if wt:
            base = _expand2(wt, r)[1]
            out += [(r / "config", base), (r / "config.worktree", base)]
    return out


# Keys whose designated directory git reads the content of (hooks executed,
# hooks copied into every new repository). For any other value, only files
# count.
DIR_KEYS = {("core", "hookspath"), ("init", "templatedir")}


_SH_SPLIT = re.compile(r"[\s;&|()<>{}=`'\"]+")
_SH_TOPLEVEL = re.compile(r"\$\(\s*git\s+rev-parse\s+--show-toplevel\s*\)"
                          r"|`\s*git\s+rev-parse\s+--show-toplevel\s*`")
_SH_PWD = re.compile(r"\$(?:PWD\b|\{PWD\})")


def _value_tokens(value: str) -> set[str]:
    """Path candidates of a config value: whitespace split, sh-style split (a
    quoted path, `!"./my tool.sh"`, is a single word for git, which hands the
    value to the shell), the whole value (programs run without a shell), and
    a split on sh operators and `=` (`./t.sh&&x`, `(./t.sh)`, `f() { ./t.sh; }`,
    `T=./t.sh`, `--rcfile=./t`). Done on the value and on its sh-expanded
    form: `$PWD`, `${PWD}` and `$(git rev-parse --show-toplevel)` are the top
    of the tree (where a `!` alias runs), other variables come from the
    environment git inherits from gitguard. [37]"""
    expanded = os.path.expandvars(_SH_PWD.sub(".", _SH_TOPLEVEL.sub(".", value)))
    toks: set[str] = set()
    for v in {value, expanded}:
        toks |= set(v.split()) | set(_SH_SPLIT.split(v))
        try:
            toks |= set(shlex.split(v))
        except ValueError:
            pass                          # unbalanced quotes: sh would refuse too
        toks.add(v.strip())
    return {t.lstrip("!").strip("\"'") for t in toks}


def _expand2(value: str, base: Path) -> tuple[Path, Path]:
    """(literal path, canonical path) — the literal detects symlinks, the
    canonical one is hashed. Like git's interpolate_path: `~/x` is $HOME/x,
    `~user/x` is that user's home (getpwnam) — only `~/` was expanded, so a
    `core.hooksPath = ~user/vol/hooks` was never watched. [50] An unknown user
    stays literal (git dies on it)."""
    p = Path(os.path.expanduser(value)) if value.startswith("~") else Path(value)
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
    """Recorded trust state. `current` false = written by an earlier version:
    to be re-validated (`retrust`), never compared."""
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
        return Manifest(1, None, [], {})     # unreadable: treated as an older format


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
        "version": FORMAT_VERSION, "root": str(repo.label),
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
    (new / ".root").write_text(str(repo.label) + "\n")
    for (scope, rel), e in man.items():
        if scope == "global":
            continue
        src = scope_base(repo, scope) / rel
        dst = new / scope / rel.lstrip("/")
        dst.parent.mkdir(parents=True, exist_ok=True)
        _copy_entry(src, dst)
        # The copy must be the file the blessed manifest describes: between
        # the diff and the answer (seconds on the tty, minutes through
        # `gitguard pending`) a still-active sandbox may have rewritten it.
        # The manifest would refuse that file at the next check, but
        # `restore` would have put the attacker's copy back. Verified on the
        # copy, in STATE, out of the sandbox's reach. A symlink's copy only
        # carries its target string, so that is what is compared.
        try:
            same = (os.readlink(dst) == os.readlink(src) if e.kind == "l"
                    else _hash_file(dst) == (e.kind, e.mode, e.sha))
        except OSError:
            same = False
        if not same:
            shutil.rmtree(new, ignore_errors=True)
            tmp.unlink(missing_ok=True)
            raise Refuse(f"{repo.label} changed while the question was pending "
                         f"({_label(scope, rel)}): not trusted, run the command again")
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


# ------------------------------------------------------------------ pending
# A git run by a program without a controlling terminal (editor, build tool,
# cron) cannot be asked and its stderr is swallowed. It records what it saw in
# `<key>.pending` and waits for the user to decide from `gitguard pending`.
# The decision channel is the reference itself: allowing = saving the reviewed
# state, which the waiter recognises as equal to its own; refusing = removing
# the record. A waiter whose state differs from what was blessed refuses.
def pending_path(key: Path) -> Path:
    return Path(str(key) + ".pending")


def load_pending(key: Path) -> dict | None:
    p = pending_path(key)
    if not p.is_file():
        return None
    try:
        d = json.loads(p.read_text())
    except (OSError, ValueError):
        return None
    return d if isinstance(d, dict) and "root" in d else None


def update_pending(key: Path, fn) -> dict | None:
    """Read-modify-write of `<key>.pending` under a lock (several waiters at
    once). `fn(current or None)` returns the record to write, or None to
    remove it."""
    STATE.mkdir(parents=True, exist_ok=True)
    STATE.chmod(0o700)
    with open(str(key) + ".pending.lock", "w") as lk:
        fcntl.flock(lk, fcntl.LOCK_EX)
        new = fn(load_pending(key))
        p = pending_path(key)
        if new is None:
            p.unlink(missing_ok=True)
        else:
            tmp = Path(str(p) + ".tmp")
            tmp.write_text(json.dumps(new, indent=1, ensure_ascii=False))
            os.replace(tmp, p)
        return new


def clear_pending(key: Path) -> None:
    # The lock file stays: unlinking it under a holder would let a third
    # process take a second "exclusive" lock on a fresh inode.
    update_pending(key, lambda _cur: None)
    Path(str(key) + ".pending.tmp").unlink(missing_ok=True)


def _alive(pid) -> bool:
    try:
        os.kill(int(pid), 0)
    except ProcessLookupError:
        return False
    except (PermissionError, TypeError, ValueError, OverflowError):
        return True
    return True


def _proc_info(pid: int) -> tuple[int, str, str] | None:
    """(ppid, name, args) of a process: /proc on Linux, /bin/ps elsewhere."""
    proc = Path(f"/proc/{pid}")
    try:
        if proc.is_dir():
            st = (proc / "stat").read_text()
            name = st[st.index("(") + 1:st.rindex(")")]        # comm may hold spaces
            ppid = int(st[st.rindex(")") + 2:].split()[1])
            args = (proc / "cmdline").read_bytes().replace(b"\0", b" ").decode(errors="replace")
            return ppid, name, args.strip()
        if not Path("/bin/ps").is_file():
            return None
        r = subprocess.run(["/bin/ps", "-o", "ppid=,comm=", "-p", str(pid)],
                           capture_output=True, text=True, timeout=3)
        line = r.stdout.strip()
        if not line:
            return None
        ppid_s, comm = line.split(None, 1)
        r = subprocess.run(["/bin/ps", "-o", "args=", "-p", str(pid)],
                           capture_output=True, text=True, timeout=3)
        return int(ppid_s), Path(comm.strip()).name, r.stdout.strip()
    except (OSError, ValueError, subprocess.SubprocessError):
        return None


def caller_chain(limit: int = 5) -> list[dict]:
    """The program that ran git, and its ancestors: [{pid, name, args}] from
    gitguard's parent upwards. Informational, sanitized; never trusted for a
    decision (it only says who to look at)."""
    out: list[dict] = []
    pid = os.getppid()
    while pid > 1 and len(out) < limit:
        info_ = _proc_info(pid)
        if info_ is None:
            break
        ppid, name, args = info_
        out.append({"pid": pid, "name": san(name)[:80], "args": san(args)[:200]})
        if ppid == pid:
            break
        pid = ppid
    return out


def notify_pending(label, text: str) -> None:
    """One desktop notification: Linux `notify-send`, macOS `osascript`. Text
    passed as arguments, never interpolated; absolute binaries; any failure
    is ignored — a notification must never change the outcome or hang git."""
    if os.environ.get("GITGUARD_NO_NOTIFY"):
        return
    title = "gitguard: decision pending"
    body = san(f"{label}: {text}")[:200]
    if Path(NOTIFY_SEND).is_file():
        cmd = [NOTIFY_SEND, "--app-name", "gitguard", "--urgency", "critical", title, body]
    elif Path(OSASCRIPT).is_file():
        cmd = [OSASCRIPT, "-e", "on run argv",
               "-e", "display notification (item 2 of argv) with title (item 1 of argv)",
               "-e", "end run", title, body]
    else:
        return
    try:
        subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=3)
    except Exception:                    # noqa: BLE001 — best effort by design
        pass


def record_pending(key: Path, kind: str, label, message: str,
                   new: dict | None = None, refs: list[tuple[str, Path]] | None = None,
                   waiter: dict | None = None) -> None:
    """Create or refresh `<key>.pending` (kind: changed | never | structural)
    and notify once per NOTIFY_COOLDOWN. `new`/`refs` (changed only) describe
    the latest state seen; `waiter` registers the blocked process."""
    now = time.time()
    notify = []

    def fn(cur: dict | None) -> dict:
        d = cur if cur and cur.get("root") == str(label) else {"created": now, "notified": 0.0,
                                                               "waiters": []}
        d.update(kind=kind, root=str(label), message=san(message), seen=now)
        if new is not None and refs is not None:
            d["entries"] = [e.__dict__ for e in sorted(new.values(), key=lambda e: (e.scope, e.path))]
            d["refs"] = [[sc, str(p)] for sc, p in refs]
        else:
            d.pop("entries", None)
            d.pop("refs", None)
        d["waiters"] = [w for w in d.get("waiters", []) if _alive(w.get("pid"))]
        if waiter is not None:
            d["waiters"].append(waiter)
        if now - float(d.get("notified") or 0) >= NOTIFY_COOLDOWN:
            d["notified"] = now
            notify.append(True)
        return d

    update_pending(key, fn)
    if notify:
        notify_pending(label, "git is waiting for your decision. In a terminal: gitguard pending"
                       if kind == "changed" else f"{message} — in a terminal: gitguard pending")


def _drop_waiter(key: Path, pid: int) -> None:
    def fn(cur: dict | None) -> dict | None:
        if cur is None:
            return None
        cur["waiters"] = [w for w in cur.get("waiters", []) if w.get("pid") != pid]
        return cur
    update_pending(key, fn)


def wait_seconds() -> float:
    v = os.environ.get("GITGUARD_WAIT")
    if v is None or v == "":
        return WAIT_DEFAULT
    try:
        f = float(v)
        if f < 0:
            raise ValueError
    except ValueError:
        raise Refuse(f"GITGUARD_WAIT must be a number of seconds: {v!r}") from None
    return f


def wait_for_decision(repo: Repo, key: Path, new: dict, refs: list[tuple[str, Path]]) -> str:
    """Record the pending state, then block until the reference equals `new`
    ("allowed"), the record disappears ("refused") or GITGUARD_WAIT elapses
    ("timeout", the record stays for `gitguard pending`)."""
    timeout = wait_seconds()
    me = {"pid": os.getpid(), "since": time.time(), "caller": caller_chain()} if timeout else None
    record_pending(key, "changed", repo.label, "has changed since the last trust", new, refs, me)
    if not timeout:
        return "timeout"
    deadline = time.monotonic() + timeout
    try:
        while True:
            old = load_manifest(key)
            if old is not None and old.current and old.entries == new:
                return "allowed"
            if load_pending(key) is None:
                return "refused"
            if time.monotonic() >= deadline:
                return "timeout"
            time.sleep(WAIT_POLL)
    finally:
        _drop_waiter(key, os.getpid())


def pending_entries(d: dict) -> dict[tuple[str, str], Entry] | None:
    try:
        return {(e["scope"], e["path"]): Entry(**e) for e in d["entries"]}
    except (KeyError, TypeError, ValueError):
        return None


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
        raise Refuse(f"no backup for {repo.label} (run 'gitguard trust' again when the repository is clean)")
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
        info(f"nothing to restore, {repo.label} is in the trusted state")
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
        info(f"{len(plan)} file(s) restored, {repo.label} matches the trusted state again")
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
    for suffix in ("", ".tmp", ".idx", ".idx.tmp", ".pending", ".pending.tmp", ".pending.lock"):
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
        if not key.is_file() and not pending_path(key).is_file():
            warn(f"not registered: {root}")
            continue
        forget_key(key)
        info(f"forgotten: {root}")


def cmd_retrust() -> None:
    n = skipped = 0
    for key, root, st in entries():
        if st in ("ok", "legacy") and root:
            save_trust(open_repo(root))
            clear_pending(key)
            n += 1
            info(f"re-trusted: {root}")
        else:
            skipped += 1
            warn(f"skipped ({st}): {root or key.name}")
    info(f"{n} repository(ies) re-trusted, {skipped} skipped")
    check_safe_bare()


def review(repo: Repo, key: Path, old: dict, new: dict, refs: list[tuple[str, Path]],
           question: str) -> bool:
    """Show what differs from the reference, ask on the terminal, and record
    exactly the state that was shown. True when recorded."""
    rule()
    warn(STYLE.bold(f"{repo.label}/.git has changed since the last trust"))
    show_changes(repo, old, new, key)
    err("")
    rule()
    if not ask_on_tty(STYLE.yellow(question)):
        return False
    save_trust(repo, refs, new)
    clear_pending(key)
    info(f"trust state recorded for {repo.label}")
    return True


def _pending_records() -> list[tuple[Path, dict]]:
    out = []
    for p in sorted(STATE.glob("????????????????.pending")):
        key = Path(str(p)[:-len(".pending")])
        d = load_pending(key)
        if d is not None:
            out.append((key, d))
    return out


def _age(ts) -> str:
    try:
        s = int(time.time() - float(ts))
    except (TypeError, ValueError):
        return "?"
    return f"{s}s" if s < 60 else f"{s // 60}min" if s < 3600 else f"{s // 3600}h{(s % 3600) // 60:02d}"


def _show_waiters(d: dict) -> list[dict]:
    alive = [w for w in d.get("waiters", []) if _alive(w.get("pid"))]
    for w in alive:
        chain = " ← ".join(f"{san(str(c.get('name', '?')))}[{c.get('pid', '?')}]" for c in w.get("caller", []))
        err(f"    git waiting (pid {w.get('pid')}, {_age(w.get('since'))}): {chain or 'unknown caller'}")
        if w.get("caller"):
            err(f"      {san(str(w['caller'][0].get('args', '')))}")
    return alive


def review_pending(key: Path, d: dict) -> None:
    label = Path(str(d["root"]))
    kind = str(d.get("kind", "?"))
    err(STYLE.bold(f"{san(label)}") + f"  [{san(kind)}, since {_age(d.get('created'))}]")
    _show_waiters(d)
    if kind != "changed":
        err(f"  {san(str(d.get('message', '')))}")
        hint("Inspect, then:  gitguard trust  (clears this record)   or:  gitguard pending -c <repo>")
        return
    repo = open_repo(label)
    refs = config_refs(repo)
    check_structure(repo, refs)
    live = manifest(repo, refs)
    old = load_manifest(key)
    if old is None or not old.current:
        raise Refuse(f"repository never trusted: {label} (gitguard trust after inspection)")
    if old.entries == live:
        clear_pending(key)
        info(f"back to the reference, nothing to decide: {label}")
        return
    recorded = pending_entries(d)
    if recorded is not None and recorded != live:
        warn("the state moved since git was blocked: this is the current one")
    if not can_ask():
        rule()
        show_changes(repo, old.entries, live, key)
        rule()
        raise Refuse("run `gitguard pending` from a terminal to decide")
    if review(repo, key, old.entries, live, refs,
              "Allow: record this state and let the waiting git run? [y/N] "):
        return
    clear_pending(key)
    warn(f"refused: the waiting git is not run; the record is cleared. If malicious:  gitguard restore")


def cmd_pending(args: list[str]) -> None:
    """`pending`: list. `pending <repo>…` / `-a`: review and decide.
    `pending -c <repo>…`: clear without deciding."""
    if args and args[0] == "-c":
        if len(args) < 2:
            raise Refuse("usage: gitguard pending -c <repo>...")
        for a in args[1:]:
            key = key_for(Path(a).resolve())
            if pending_path(key).is_file():
                clear_pending(key)
                info(f"cleared: {Path(a).resolve()}")
            else:
                warn(f"nothing pending: {Path(a).resolve()}")
        return
    records = _pending_records()
    if not args:
        if not records:
            info("nothing pending")
            return
        for key, d in records:
            n = sum(_alive(w.get("pid")) for w in d.get("waiters", []))
            colors = {"changed": STYLE.yellow, "never": STYLE.red, "structural": STYLE.red}
            kind = str(d.get("kind", "?"))
            err(f"{colors.get(kind, str)(f'{kind:<11}')} {_age(d.get('created')):>6}  "
                f"{n} waiting  {san(str(d['root']))}")
        hint("gitguard pending <repo>   to see the diff and decide     -a: all")
        return
    if args == ["-a"]:
        targets = records
    else:
        targets = []
        for a in args:
            key = key_for(Path(a).resolve())
            d = load_pending(key)
            if d is None:
                warn(f"nothing pending: {Path(a).resolve()}")
            else:
                targets.append((key, d))
    for key, d in targets:
        review_pending(key, d)


# -------------------------------------------------------- exec mode (git …)
# git.c handle_options(): options taking a separate argument, options also
# accepted as `--opt=value`, and flags. Anything else is refused: an unknown
# option may take an argument, and guessing wrong made gitguard take
# `--config-env`'s argument for the subcommand, ignore the `-C` that followed
# and check another directory than git's. git refuses unknown options too. [40]
GLOBAL_WITH_ARG = {"-c", "--config-env", "--namespace", "-C", "--git-dir", "--work-tree",
                   "--attr-source", "--shallow-file", "--super-prefix"}
GLOBAL_WITH_EQ = ("--config-env=", "--namespace=", "--git-dir=", "--work-tree=",
                  "--attr-source=", "--shallow-file=", "--super-prefix=", "--exec-path=",
                  "--list-cmds=")
GLOBAL_FLAGS = {"-p", "--paginate", "-P", "--no-pager", "--no-replace-objects", "--bare",
                "--literal-pathspecs", "--no-literal-pathspecs", "--glob-pathspecs",
                "--noglob-pathspecs", "--icase-pathspecs", "--no-optional-locks",
                "--no-advice", "--no-lazy-fetch", "--exec-path", "--html-path",
                "--man-path", "--info-path"}
GLOBAL_STOP = {"-h", "--help", "-v", "--version"}   # git turns them into a command


@dataclass
class GlobalOpts:
    cwd: Path                 # effective cwd after the -C options (not canonicalised)
    gitdir: Path | None       # --git-dir, relative to that cwd
    worktree: Path | None     # --work-tree, relative to that cwd
    rest: list[str]           # from the subcommand onwards
    config: list[str] = field(default_factory=list)      # -c arguments (`key=value`)
    config_env: list[str] = field(default_factory=list)  # --config-env arguments (`key=VAR`)


def split_global_options(args: list[str], cwd: Path) -> GlobalOpts:
    """Interpret git's global options as git would, without side effects.
    `--work-tree` does **not** change gitdir discovery — git does it from the
    cwd (or GIT_DIR); moving there made gitguard check another repository
    while git executed the config of the cwd's repository [18]. It does
    however designate the tree to check when `--git-dir` is given [28].
    git applies each `-C` at once but only stores `--git-dir`/`--work-tree`
    (setenv): a relative one is resolved from the *final* cwd —
    `--git-dir=.git -C repo` is `repo/.git`. [41]"""
    gitdir: str | None = None
    worktree: str | None = None
    config: list[str] = []
    config_env: list[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        if a in GLOBAL_WITH_ARG:
            if i + 1 >= len(args):
                raise Refuse(f"option {a} without an argument")
            v = args[i + 1]
            i += 2
            if a == "-C":
                cwd = cwd / v
            elif a == "--git-dir":
                gitdir = v
            elif a == "--work-tree":
                worktree = v
            elif a == "-c":
                config.append(v)
            elif a == "--config-env":
                config_env.append(v)
        elif a.startswith(GLOBAL_WITH_EQ):
            i += 1
            opt, v = a.split("=", 1)
            if opt == "--git-dir":
                gitdir = v
            elif opt == "--work-tree":
                worktree = v
            elif opt == "--config-env":
                config_env.append(v)
        elif a in GLOBAL_FLAGS:
            i += 1
        elif a in GLOBAL_STOP or not a.startswith("-"):
            break
        else:
            raise Refuse(f"unknown git global option {a!r}: gitguard cannot tell "
                         f"which repository git would use")
    return GlobalOpts(cwd, None if gitdir is None else cwd / gitdir,
                      None if worktree is None else cwd / worktree, args[i:], config, config_env)


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
    CLI_CONFIG[:] = o.config
    CLI_CONFIG_ENV[:] = o.config_env
    return orig


CLONE_WITH_ARG = {"-o", "-b", "--branch", "--origin", "-u", "--upload-pack", "--reference",
                  "--depth", "--jobs", "-j", "--config", "--filter", "--shared",
                  "--object-format", "--initial-branch", "--ref-format", "--template"}


def _template_dir_configured(cli_config: list[str]) -> bool:
    """A template directory copies hooks into every new repository: like
    `--template=`, it rules out auto-trust. Every source git reads: the
    global/system config *and the files it includes*, `-c`/`--config-env`,
    GIT_CONFIG_COUNT/KEY_n, GIT_CONFIG_PARAMETERS, GIT_TEMPLATE_DIR. [42]"""
    if os.environ.get("GIT_TEMPLATE_DIR"):
        return True
    if "init.templatedir" in os.environ.get("GIT_CONFIG_PARAMETERS", "").lower():
        return True
    keys = [c.split("=", 1)[0] for c in cli_config]
    keys += [v for k, v in os.environ.items() if k.startswith("GIT_CONFIG_KEY_")]
    if any(k.strip().lower() == "init.templatedir" for k in keys):
        return True
    queue, seen = list(global_config_files()), set()
    for _ in range(INCLUDE_DEPTH + 1):
        nxt = []
        for f in queue:
            if f in seen or not f.is_file():
                continue
            seen.add(f)
            for section, key, value in parse_git_config(f):
                if section == "init" and key == "templatedir":
                    return True
                if section.startswith("include") and key == "path":
                    nxt.append(_expand2(value, f.parent)[1])
        queue = nxt
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
    if template or _template_dir_configured(o.config + o.config_env):
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


def run_git(args: list[str], orig: Path, newrepo: tuple[str, Path] | None, git: str) -> int:
    os.chdir(orig)
    if newrepo is None:
        os.execv(git, [git, *args])
    sub, d = newrepo
    preexisting = (d / ".git").exists() or (d / ".git").is_symlink()
    rc = subprocess.call([git, *args])
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
    (the diff just shown was not seen), when stdout is not a terminal (a
    `$(git …)` run by a shell prompt has stderr on the terminal and stdout on
    a pipe: asking there would block every prompt redraw on a modified
    repository; the price is that `git log | head` is refused instead of
    asked) or when GITGUARD_NO_PROMPT is set."""
    if not can_ask():
        return False
    try:
        # Two opens: "r+" in text mode requires a seekable stream.
        with open("/dev/tty", "w") as out, open("/dev/tty") as inp:
            # Keystrokes typed before the diff was on screen must not answer
            # it: flush them before the question is written.
            termios.tcflush(inp.fileno(), termios.TCIFLUSH)
            out.write(san(question))
            out.flush()
            ans = inp.readline()
    except OSError:
        return False
    return ans.strip().lower() in ("y", "yes")


def has_tty() -> bool:
    """A controlling terminal exists (the process was started from a shell,
    not by an editor, a build daemon or cron). Probed without opening
    /dev/tty: on macOS, opening and closing it in a session leader whose pty
    master is not being read leaves the process stuck in its exit (tty output
    drain at revoke) — seen in the pty tests. Linux: tty_nr of /proc/self/stat;
    elsewhere `ps -o tty=`. Unknown → True: the immediate refusal is the
    conservative answer (nobody is left waiting)."""
    try:
        st = Path("/proc/self/stat").read_text()
        return int(st[st.rindex(")") + 2:].split()[4]) != 0        # tty_nr
    except (OSError, ValueError, IndexError):
        pass
    try:
        r = subprocess.run(["/bin/ps", "-o", "tty=", "-p", str(os.getpid())],
                           capture_output=True, text=True, timeout=3)
        tty = r.stdout.strip()
        return bool(tty) and tty not in ("??", "?", "-")
    except (OSError, subprocess.SubprocessError):
        return True


def can_ask() -> bool:
    return (not os.environ.get("GITGUARD_NO_PROMPT") and sys.stderr.isatty()
            and sys.stdout.isatty() and has_tty())


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
        raise Refuse(f"repository {why}: {repo.label}\n  Inspect .git/config and .git/hooks, then:  "
                     + STYLE.cyan("gitguard trust"))
    if old.entries == new:
        if pending_path(key).is_file():
            clear_pending(key)           # the state came back on its own
        return
    if interactive:
        branches = auto_accept(repo, key, old, new)
        if branches:
            save_trust(repo, refs, new)
            info(f"config: branch tracking for {', '.join(san(b) for b in branches)} "
                 f"→ reference updated")
            return
    rule()
    warn(STYLE.bold(f"{repo.label}/.git has changed since the last trust"))
    show_changes(repo, old.entries, new, key)
    err("")
    rule()
    if interactive and ask_on_tty(STYLE.yellow(
            "Trust this state and run git? [y/N] ")):
        save_trust(repo, refs, new)
        clear_pending(key)
        info(f"trust state recorded for {repo.label}")
        return
    if interactive and not has_tty():
        # Run by a program (editor, build, cron): nobody reads this. Record
        # the state and wait for `gitguard pending`; shortcut 3.
        outcome = wait_for_decision(repo, key, new, refs)
        if outcome == "allowed":
            info(f"allowed through gitguard pending: {repo.label}")
            return
        e = Refuse("refused through gitguard pending." if outcome == "refused" else
                   f"no decision within {wait_seconds():g} s: refusing to run git. "
                   f"In a terminal:  gitguard pending")
        e.recorded = True
        raise e
    hint("If legitimate:  gitguard trust      Otherwise:  gitguard restore")
    raise Refuse("refusing to run git.")


def main(argv: list[str]) -> int:
    mode, yes = "check", False
    if Path(argv[0]).name == "git":
        mode, argv = "exec", argv[1:]    # invoked through a symlink named git
    else:
        argv = argv[1:]
        cmd = argv[0] if argv else ""
        if cmd and cmd not in ("help", "-h", "--help", "git"):
            set_output(sys.stdout)       # a management command: its output is the result
        if cmd in ("trust", "diff"):
            mode, argv = cmd, argv[1:]
        elif cmd == "restore":
            mode, argv = "restore", argv[1:]
            if argv and argv[0] == "-y":
                yes, argv = True, argv[1:]
        elif cmd == "git":
            mode, argv = "exec", argv[1:]
        elif cmd == "list":
            cmd_list(); argv = argv[1:]
        elif cmd == "forget":
            cmd_forget(argv[1:]); return 0
        elif cmd == "pending":
            cmd_pending(argv[1:]); return 0
        elif cmd == "prune":
            cmd_forget(["--missing"]); argv = argv[1:]
        elif cmd == "retrust":
            cmd_retrust(); argv = argv[1:]
        elif cmd in ("help", "-h", "--help"):
            print(__doc__); return 0
        elif cmd:
            # A typo (`gitguard tust`) used to fall through to a silent check
            # whose exit 0 looked like a success of the intended command.
            raise Refuse(f"unknown command {cmd!r} (see gitguard help)")
        if mode != "exec" and argv:
            raise Refuse(f"{cmd or 'check'} takes no argument: {' '.join(argv)!r}")
        if cmd in ("list", "prune", "retrust"):
            return 0

    orig = Path.cwd()
    newrepo, git = None, ""
    if mode == "exec":
        newrepo = parse_new_repo(argv)
        orig = apply_global_options(argv)
    # A refusal that nobody will read (exec mode, no controlling terminal) is
    # recorded for `gitguard pending`. The "changed" case records itself
    # (and waits); here the never-trusted and structural ones.
    label: Path = Path.cwd()
    key: Path | None = None
    old: Manifest | None = None
    fingerprinted = False
    try:
        if mode == "exec":
            git = real_git()             # resolved first: no git at all is its own error
        root = find_root(Path.cwd())
        if root is None:
            if mode == "exec":
                return run_git(argv, orig, newrepo, git)
            if mode != "check":
                raise Refuse(f"no git repository here: {Path.cwd()}")      # [30]
            return 0
        repo = open_repo(root)
        label, key = repo.label, repo.key
        refs = config_refs(repo)
        check_structure(repo, refs)
        new = manifest(repo, refs)
        old = load_manifest(key)
        fingerprinted = True
    except Refuse as e:
        if mode == "exec" and not e.recorded and not has_tty():
            kind = "never" if fingerprinted and (old is None or not old.current) else "structural"
            record_pending(key or key_for(Path.cwd().resolve()), kind, label, str(e))
            e.recorded = True
        raise

    if mode == "trust":
        if old is not None and old.current and old.entries != new:
            # A changed repository: the diff first, so that `trust` is never
            # typed blind; on a terminal, a question; in a script, recorded.
            if can_ask():
                if not review(repo, key, old.entries, new, refs,
                              "Record this state as the reference? [y/N] "):
                    raise Refuse("not trusted.")
                check_safe_bare()
                return 0
            rule()
            warn(STYLE.bold(f"{repo.label}/.git has changed since the last trust"))
            show_changes(repo, old.entries, new, key)
            rule()
        save_trust(repo, refs, new)
        clear_pending(key)
        info(f"trust state recorded for {repo.label}")
        wt = [f"{s}:{p}" for s, p in refs]
        if wt:
            hint(f"the config references outside the gitdir: {' '.join(wt)} → watched too")
        # A directory in the refs comes from DIR_KEYS (hooksPath, templateDir). [44]
        intree = [p for s, p in refs if s == "wt" and p.is_dir()]
        if intree:
            warn(f"hooks in the work tree ({' '.join(str(p.relative_to(repo.root)) for p in intree)}): "
                 f"if git tracks them, a checkout/merge/reset/pull of a commit someone else "
                 f"created replaces them after the check, and git runs the new version in the "
                 f"same command. Review incoming changes to these files.")
        check_safe_bare()
        return 0
    if mode == "diff":
        if old is None:
            raise Refuse(f"no trust state for {repo.label} (gitguard trust)")
        if old.entries == new:
            info(f"no changes in {repo.label}")
        else:
            err(STYLE.yellow(STYLE.bold(f"changes in {san(repo.label)}/.git:")))
            show_changes(repo, old.entries, new, key)
        return 0
    if mode == "restore":
        if old is None:
            raise Refuse(f"no trust state for {repo.label} (gitguard trust)")
        restore(repo, key, old.entries, new, yes, old.refs)
        return 0

    try:
        check_or_die(repo, key, old, new, refs, interactive=(mode == "exec"))
    except Refuse as e:
        if mode == "exec" and not e.recorded and not has_tty():
            kind = "never" if old is None or not old.current else "structural"
            record_pending(key, kind, label, str(e))
            e.recorded = True
        raise
    if mode == "exec":
        return run_git(argv, orig, newrepo, git)
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
