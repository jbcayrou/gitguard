#!/usr/bin/env python3
"""gitguard — refuses to run git on a repository whose "trusted" files have
changed since the user last validated them.

Usage:
  gitguard               check the current repository (exit 1 if suspect or never trusted)
  gitguard trust         record the current state as the reference (+ backup)
  gitguard diff          show what differs from the reference
  gitguard restore [-y]  put the watched files of the gitdir and the tree back
                         into the reference state (a file outside the repository
                         is named, never written)
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

Threat model, design choices and vulnerability history: see DESIGN.md.
"""
from __future__ import annotations

# Only what every command needs: each `gitguard git …` pays these imports
# (about 12 ms of the 45 ms overhead before this trim). `subprocess`, `shutil`,
# `difflib`, `termios`, `fcntl` and `dataclasses` are imported where used —
# trust, restore, pending, a prompt — never on the check-then-exec path.
import hashlib
import json
import os
import re
import shlex
import stat
import sys
import time
from collections.abc import Iterator
from functools import cached_property
from pathlib import Path

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
    me = Path(__file__).resolve()
    if os.environ.get("GITGUARD_REAL_GIT"):
        v = os.environ["GITGUARD_REAL_GIT"]
        try:
            looped = Path(v).resolve() == me
        except OSError:
            looped = False
        if looped:          # `<exec-path>/git` after the diversion: gitguard would exec itself for ever
            raise Refuse(f"GITGUARD_REAL_GIT names gitguard itself: {v}")
        return v

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
def state_dir() -> Path:
    """Where the trust states live: `GITGUARD_STATE`, else `$XDG_STATE_HOME/gitguard`,
    else `~/.local/state/gitguard`. XDG_STATE_HOME is the specified home for
    per-machine, non-portable state (the manifests are bound to this host's
    absolute paths and regenerated by `trust`); the spec says a relative value
    is invalid and must be ignored. Never inside a mounted volume: this is
    where the reference is, and the environment is the user's, not the
    sandbox's."""
    explicit = os.environ.get("GITGUARD_STATE")
    if explicit:
        return Path(explicit)
    xdg = os.environ.get("XDG_STATE_HOME", "")
    if xdg.startswith("/"):
        return Path(xdg) / "gitguard"
    return Path.home() / ".local/state/gitguard"


STATE = state_dir()
WAIT_DEFAULT = 60.0      # seconds a git without a controlling terminal waits for `gitguard pending`
WAIT_POLL = 0.5
NOTIFY_COOLDOWN = 600    # one desktop notification per repository per 10 minutes
NOTIFY_SEND = "/usr/bin/notify-send"     # absolute: a PATH entry may live in the volume
OSASCRIPT = "/usr/bin/osascript"
INCLUDE_DEPTH = 10      # git: MAX_INCLUDE_DEPTH = 10
# No walk of the work tree looking for nested `.git`: git opens a nested
# repository through a gitlink — of the index, read at every command
# (`index_gitlinks`, sparse directories included [87]), or brought by the
# command from a tree, which the child git that enters it — gitguard, at
# the exec path — refuses as never trusted ([66], [86], [89]; DESIGN-exec-path.md) —
# and the `git add -A` that creates an index gitlink executes nothing by itself (tests/nested_git_is_a_threat.sh,
# test_first_add_does_not_execute). The command that FOLLOWS the `add` is
# refused. A walk (`GITGUARD_SCAN_TREE`, removed 2026-10-18) only closed the
# window between that `add` and the next wrapped command — a window only a
# git outside the wrapper can exploit, which is out of scope by design — for
# +0.2 s per command on the Linux kernel. See DESIGN.md, "Nested repositories".

# Volatile: what git rewrites during normal operation. Everything else in the
# gitdir is watched (deny-by-default inversion, see DESIGN.md).
#
# Every entry is a path **relative to a gitdir root** (the gitdir itself, or
# `modules/<x>/`, `worktrees/<x>/`, recognised by the presence of a HEAD or
# commondir file, _child_root): `refs` is `<root>/refs` and nothing else,
# `objects/pack` is under the root's `objects/`. Anchoring by construction:
# a submodule named `lfs` or `refs` made its whole gitdir invisible when the
# names applied at any depth [15]; `info/refs` tested against the gitdir base
# instead of the closest root alerted on `git gc` in a submodule [26]. The
# universe these tables classify is git's own: tests/inventory/ lists every
# name git opens under a gitdir, test_claims.py holds each one to an entry
# here, a reader (VOLATILE_READERS) or a deliberate hash.
# `reftable`: the refs of a `--ref-format=reftable` repository (tables and
# tables.list, rewritten on every ref update, like refs/ and packed-refs;
# nothing git runs). Fingerprinted, every commit alerted. [64]
VOLATILE_DIRS = {"refs", "logs", "lfs", "rr-cache", "rebase-merge", "rebase-apply",
                 "sequencer", "filter-repo", "reftable",
                 "objects/pack", "objects/info/commit-graphs"}
# `ADD_EDIT.patch`, `NOTES_EDITMSG`, `REPLACE_EDITOBJ`: the edit buffers of
# `add -e`, `notes add|edit`, `replace --edit`, left behind when the editor
# fails (`:cq`) or changes nothing; `MERGE_LABELS` and `rebased-patches`, the
# same class (data git applies to the index or the objects, both volatile,
# never a program). Every following command was refused. [100]
VOLATILE_FILES = {"index", "HEAD", "ORIG_HEAD", "FETCH_HEAD", "MERGE_HEAD", "MERGE_MSG",
                  "MERGE_MODE", "MERGE_RR", "MERGE_AUTOSTASH", "AUTO_MERGE", "REBASE_HEAD",
                  "CHERRY_PICK_HEAD", "REVERT_HEAD", "SQUASH_MSG", "COMMIT_EDITMSG",
                  "TAG_EDITMSG", "packed-refs", "shallow", "gc.log", "gc.pid",
                  "commit-graph", "multi-pack-index", "locked", "EDIT_DESCRIPTION",
                  "ADD_EDIT.patch", "NOTES_EDITMSG", "REPLACE_EDITOBJ", "MERGE_LABELS",
                  "rebased-patches",
                  "info/refs", "objects/info/packs", "objects/info/commit-graph",
                  "objects/info/multi-pack-index", "info/sparse-checkout"}
OBJECT_FANOUT = re.compile(r"^objects/[0-9a-f]{2}$")
# Volatile files git reads back as instructions cannot be hashed (rewritten
# at every step) and cannot be ignored: each has a reader that refuses what
# would run — VOLATILE_READERS, after the readers. [19] [51]
BUILTIN_MERGE_STRATEGIES = {"ort", "recursive", "resolve", "octopus", "ours", "subtree"}


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


def read_file(p: Path) -> bytes:
    """The bytes of a file of the repository that git reads (config, gitfile,
    commondir, index, todo files…), never blocking. Opened O_NONBLOCK, then
    fstat: a FIFO in place of `.git/config` blocked gitguard in read() for
    ever — fail closed, but a denial of service that pushes the user toward
    the real git — so anything but a regular file is refused at once (a
    FIFO, a socket, a device, a symlink to one). /dev/null reads empty, as
    for git (`GIT_CONFIG_GLOBAL=/dev/null`). A directory or a missing file
    raises the OSError read_bytes() raised. [99]"""
    fd = os.open(p, os.O_RDONLY | os.O_NONBLOCK)
    try:
        st = os.fstat(fd)
        if stat.S_ISDIR(st.st_mode):
            raise IsADirectoryError(f"{p}: is a directory")
        if not stat.S_ISREG(st.st_mode):
            if stat.S_ISCHR(st.st_mode) and st.st_rdev == os.stat(os.devnull).st_rdev:
                return b""
            raise Refuse(f"{p} is not a regular file (a FIFO, a socket or a device): git "
                         f"would read it, gitguard cannot check it without blocking")
        chunks = []
        while chunk := os.read(fd, 1 << 16):
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def is_file(p: Path) -> bool:
    """`p.is_file()` for a file git reads: a FIFO, a socket or a device there
    is refused rather than skipped (git would read it, read_file). [99]"""
    try:
        st = p.stat()
    except OSError:
        return False
    if stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode):
        return stat.S_ISREG(st.st_mode)
    read_file(p)                     # refuses; /dev/null: nothing to read
    return False


def parse_git_config(path: Path) -> list[tuple[str, str, str]]:
    """Return [(section, key, value)], section lower-cased with its subsection
    ("includeIf.gitdir:x"), key lower-cased, exactly as git reads them. Never
    via `git config`: git would honour the very config we are trying to judge.
    A NUL byte makes git truncate the value (C string): refused instead, a
    config is never meant to contain one. Read as bytes: text mode would turn
    a lone CR into a newline, where git sees whitespace inside the value
    (`hooksPath = .githooks<CR>x = y` is one value for git). [52]"""
    try:
        text = read_file(path).decode(errors="surrogateescape")
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


def config_last(path: Path, section: str, key: str) -> str | None:
    """The value git keeps for `section.key` from one file: the last one
    (each config callback overwrites the previous), None when absent. A
    reader that returned at the first match diverged from git. [84]"""
    value = None
    for s, k, v in parse_git_config(path):
        if s == section and k == key:
            value = v
    return value


# ---------------------------------------------------------- repo / gitdir
def key_for(root: Path) -> Path:
    """State key of a repository: first 16 hex digits of the sha256 of its canonical root."""
    return STATE / hashlib.sha256(str(root).encode()).hexdigest()[:16]


class Repo:
    root: Path        # work tree root, canonical (core.worktree honoured)
    gitdir: Path      # real gitdir (resolved if gitfile)
    common: Path      # commondir (== gitdir outside a linked worktree)
    # Directory whose `.git` was discovered: the state key and `.root` are
    # derived from it, not from a `core.worktree` the config may redirect
    # the tree to (that redirection is itself a config change). [47]
    anchor: Path | None

    def __init__(self, root: Path, gitdir: Path, common: Path,
                 anchor: Path | None = None) -> None:
        self.root, self.gitdir, self.common, self.anchor = root, gitdir, common, anchor

    def __repr__(self) -> str:
        return f"Repo({self.root!r}, {self.gitdir!r}, {self.common!r}, {self.anchor!r})"

    @property
    def key(self) -> Path:
        return key_for(self.anchor or self.root)

    @property
    def label(self) -> Path:
        """How the repository is named to the user: the directory holding `.git`."""
        return self.anchor or self.root

    @property
    def index(self) -> Path:
        """The index git reads: `GIT_INDEX_FILE` when set — absolute, or
        relative to the work tree root git chdirs to before opening it (from
        a subdirectory too: `rev-parse --git-path index` says so) — else the
        gitdir's. The gitlinks of a scratch index in the volume were not
        read. [54]"""
        v = os.environ.get("GIT_INDEX_FILE")
        return self.gitdir / "index" if v is None else self.root / v

    @cached_property
    def gitfiles(self) -> list[Path]:
        """Every nested `.git` to check: those declared in `.gitmodules` and
        those referenced by an index gitlink, wherever they are
        (`node_modules/pkg` included). [6] [14] [24]"""
        out = set(gitmodules_gits(self.root))
        out |= index_nested(self.root, *index_entries(self.index, Path(str(self.key) + ".idx"),
                                                      object_id_size(self.common)))
        return sorted(out)


# --------------------------------------------------------------- discovery
# Port of git's repository discovery (setup.c, path.c), the one part of
# gitguard that must agree with git *before* anything is read: a
# divergence here checks a repository git does not open, or lets through
# one it does ([23] [28] [47] [49] [53] [54]). Each function names the git
# function it mirrors. The ports were written against git 2.50 and are
# checked by `pytest -m discovery` (tests/test_git_parity.py, git as the
# oracle; the header of every run names the git used): run it after a git
# upgrade, and re-read the git function when it fails.
#
#   _validate_headref   validate_headref        (setup.c)
#   is_bare_gitdir      is_git_directory        (setup.c)
#   find_root           setup_git_directory_gently_1 (setup.c): `.git` file or
#                       directory first, the directory itself second, the
#                       ceiling and the device boundary where git stops
#   _ceiling_offset     longest_ancestor_length (path.c) + canonicalize_ceiling_entry
#   _env_bool           git_env_bool            (config.c)
#   _read_path_file     read_gitfile_gently / get_common_dir_noenv (setup.c):
#                       one path, trailing CR/LF trimmed, nothing else
#   read_gitfile        read_gitfile_gently     (setup.c)
#   open_repo           setup_discovered_git_dir + get_common_dir_noenv (setup.c)
#   _core_worktree      check_repository_format_gently / check_repo_format
#                       (setup.c): core.worktree, last value, as is,
#                       config.worktree with extensions.worktreeConfig
#   env_common_dir      GIT_COMMON_DIR as environment.c and setup.c take it
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
        buf = read_file(p)[:255].split(b"\0", 1)[0]
    except OSError:
        return False
    if buf.startswith(b"ref:") and buf[4:].lstrip(b" \t\r\n").startswith(b"refs/"):
        return True
    return re.match(rb"[0-9a-fA-F]{40}", buf) is not None


def env_common_dir() -> Path | None:
    """`GIT_COMMON_DIR`: git takes it as the common dir in every case — in
    discovery (`is_git_directory` looks for `objects` and `refs` there, so a
    lone `HEAD` makes any directory a gitdir) and once the repository is open
    (`config`, `hooks/`, `info/`, `objects/`, `worktrees/` come from it; the
    `commondir` file is ignored). gitguard read the gitdir's own files and
    fingerprinted a repository git was not using. [54]

    A relative value is read by git against the cwd during discovery, then
    against the work tree root it has chdir'ed to: `../x` from a
    subdirectory finds no repository at all, `../../x` finds one and reads
    an empty config. Refused rather than picking one of the two."""
    v = os.environ.get("GIT_COMMON_DIR")
    if v is None:
        return None
    if not v.startswith("/"):
        raise Refuse(f"GIT_COMMON_DIR={v!r}: gitguard needs an absolute path (git reads a "
                     f"relative one against two different directories in one run)")
    return Path(v)


def is_bare_gitdir(d: Path, env: bool = True) -> bool:
    """git's is_git_directory, the test behind its discovery: a valid HEAD,
    then `objects` and `refs` reachable (access X_OK) in the common dir — the
    directory itself, or what its `commondir` file names. This is how git
    recognises a bare repository, or any directory a container has stuffed
    with these names. The former "HEAD file + objects/ + refs/ here" missed a
    `HEAD` symlink and a `commondir` redirection git accepts. [49]
    `env=False` for another repository git enters as a transport (a local
    remote, [61]): git clears GIT_COMMON_DIR, GIT_OBJECT_DIRECTORY… for that
    child (local_repo_env)."""
    if not _validate_headref(d / "HEAD"):
        return False
    common = (env_common_dir() if env else None) or d
    cd = d / "commondir"
    if common == d and cd.is_file():
        try:
            common = d / _read_path_file(cd)     # a Refuse (NUL) propagates: git
        except OSError:                          # truncates and opens the dir,
            return False                         # "not a gitdir" would walk past it
    objects = Path(os.environ["GIT_OBJECT_DIRECTORY"]) \
        if env and os.environ.get("GIT_OBJECT_DIRECTORY") else common / "objects"
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
        gd = Path(os.environ["GIT_DIR"])
        # A GIT_DIR that is no git directory (missing, or a directory without
        # a valid HEAD, objects and refs): setup_explicit_git_dir leaves git
        # outside any repository (it dies, or a command such as `init` runs
        # repository-less) and no local config is read. `git --bare init` in
        # an empty directory. [97] A gitfile is followed by git: not here.
        if not gd.exists() or (gd.is_dir() and not is_bare_gitdir(gd)):
            return None
        wt = os.environ.get("GIT_WORK_TREE")
        if wt:
            return Path(wt).resolve()
        env = env_common_dir()
        wt = _core_worktree(gd, env or gd, env is not None or (gd / "commondir").is_file())
        return cwd.resolve() if wt is None else wt
    d = cwd.resolve()
    # Where git stops ascending, gitguard stops too, or it checks — and refuses
    # on — a repository git would not open (seen with a tmpfs mounted inside
    # a modified repository, and with GIT_CEILING_DIRECTORIES). Port of
    # setup.c: the ceiling directories are the longest one that is a proper
    # ancestor of the cwd and are never entered; a parent on another device
    # is never entered unless GIT_DISCOVERY_ACROSS_FILESYSTEM.
    ceil = _ceiling_offset(d)
    one_fs = not _env_bool("GIT_DISCOVERY_ACROSS_FILESYSTEM")
    try:
        dev = d.stat().st_dev
    except OSError:
        dev = None
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
                         f"handled by gitguard) or booby-trapped directory. Run the real git "
                         f"directly (`git.real`, or the one GITGUARD_REAL_GIT names) if "
                         f"intended; {SAFE_BARE_HINT}.")
        if d.parent == d:
            return None
        if ceil is not None and len(str(d.parent)) <= ceil:
            return None               # GIT_DIR_HIT_CEILING
        if one_fs and dev is not None:
            try:
                if d.parent.stat().st_dev != dev:
                    return None       # GIT_DIR_HIT_MOUNT_POINT
            except OSError:
                return None
        d = d.parent


def _env_bool(name: str) -> bool:
    """git_env_bool: unset or empty is false; else git's boolean parsing."""
    v = os.environ.get(name, "")
    return v.strip().lower() in ("1", "true", "yes", "on") if v else False


def _ceiling_offset(cwd: Path) -> int | None:
    """longest_ancestor_length: the length of the longest GIT_CEILING_DIRECTORIES
    entry that is a proper ancestor of `cwd`, None when there is none. Entries
    are canonicalised (`real_path`) until an empty entry, after which they are
    taken literally — git's rule, to spare a slow filesystem."""
    raw = os.environ.get("GIT_CEILING_DIRECTORIES")
    if not raw:
        return None
    best, literal, s = None, False, str(cwd)
    for entry in raw.split(os.pathsep):
        if entry == "":
            literal = True
            continue
        if not entry.startswith("/"):
            continue
        if not literal:
            try:
                entry = str(Path(entry).resolve())
            except OSError:
                continue
        entry = entry.rstrip("/") or "/"
        prefix = entry if entry == "/" else entry + "/"
        if s.startswith(prefix) and s != entry:
            best = max(best or -1, len(entry))
    return best


def _read_path_file(p: Path) -> str:
    """A file git reads as one path (`commondir`, the gitfile's `gitdir:`): the
    whole content, every trailing CR/LF trimmed, nothing else — no strip(), no
    line split: `x<SPACE>`, `x<CR>y` or a second line are part of the path for
    git, which then finds no repository there and dies. Reading them more
    leniently made gitguard check a repository git never opens. NUL: git
    truncates (C string), refused here. [53]"""
    buf = read_file(p)
    if b"\0" in buf:
        raise Refuse(f"{p}: NUL byte")
    return buf.rstrip(b"\r\n").decode(errors="surrogateescape")


def read_gitfile(p: Path) -> Path:
    """read_gitfile_gently: `gitdir: ` at the very start of the file, then the
    path as _read_path_file reads it, relative to the file's directory."""
    text = _read_path_file(p)
    if not text.startswith("gitdir: ") or len(text) == 8:
        raise Refuse(f"{p}: invalid .git file")
    target = Path(text[8:])
    return _resolve_existing(target if target.is_absolute() else p.parent / target, p)


def _resolve_existing(path: Path, src: Path) -> Path:
    """resolve(strict=True): the OS walk git's own access does. Non-strict
    resolve() cancels `x/..` lexically once `x` is missing (` ../..` became the
    parent where git finds no directory and dies). [53]"""
    try:
        return path.resolve(strict=True)
    except (OSError, RuntimeError):
        raise Refuse(f"{src} names a path that does not exist: {path}") from None


def _core_worktree(gitdir: Path, common: Path, has_common: bool) -> Path | None:
    """The work tree `core.worktree` designates, read as git's
    check_repository_format_gently reads it (setup.c, check_repo_format):
    the common config's last value; with `extensions.worktreeConfig` this
    gitdir's `config.worktree` is read too, its value wins and has_common
    is cleared; applied only `if (!has_common)` — never in a linked
    worktree, whose `commondir` (or GIT_COMMON_DIR) sets has_common ([76]:
    a submodule's linked worktree took `.git/modules/<x>` for its tree).
    The value is copied as is (xstrdup): no `~`, no variable — git dies on
    `chdir '~/t'` and so does a missing directory; refused here rather than
    checking a tree git never opens. Relative to the gitdir. [47] [84]"""
    cfg = common / "config"
    wt = config_last(cfg, "core", "worktree")
    ext = config_last(cfg, "extensions", "worktreeconfig")
    if ext is not None and ext.lower() in ("true", "yes", "on", "1"):
        has_common = False
        wt2 = config_last(gitdir / "config.worktree", "core", "worktree")
        if wt2 is not None:
            wt, cfg = wt2, gitdir / "config.worktree"
    if not wt or has_common:
        return None
    return _resolve_existing(gitdir / wt, cfg)


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
    env = env_common_dir()
    if env is not None:                          # the commondir file is ignored [54]
        if not env.is_dir():
            raise Refuse(f"GIT_COMMON_DIR names no directory: {env}")
        common = env.resolve()
    elif cd.is_file():
        common = _resolve_existing(g / _read_path_file(cd), cd)
        if not common.is_dir():
            raise Refuse(f"{cd} names no directory: {common}")
    anchor = root
    wt_env = os.environ.get("GIT_WORK_TREE")
    if wt_env and not os.environ.get("GIT_DIR"):
        # --work-tree / GIT_WORK_TREE without --git-dir: git discovers the
        # gitdir from the cwd ([18]) and then takes the given directory as
        # the tree (setup_discovered_git_dir → setup_explicit_git_dir, the
        # environment before core.worktree), where a relative core.hooksPath
        # resolves; the discovered tree was checked instead. [72] (With
        # --git-dir, find_root already returned it, [28].)
        root = Path(wt_env).resolve()
        if not root.is_dir():
            raise Refuse(f"GIT_WORK_TREE names no directory: {wt_env}")
    elif not os.environ.get("GIT_DIR"):
        # core.worktree: git takes that directory as the work tree and
        # resolves a relative core.hooksPath there; the directory containing
        # `.git` was kept, and the hooks never watched. [47] Read as git
        # reads it (_core_worktree; with GIT_DIR, find_root did it). [76] [84]
        wt = _core_worktree(g, common, env is not None or cd.is_file())
        if wt is not None:
            root = wt
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


def index_gitlinks(index: Path, cache: Path | None = None, oid_size: int = 20) -> list[str]:
    """The gitlinks of `index_entries`."""
    return index_entries(index, cache, oid_size)[0]


def index_entries(index: Path, cache: Path | None = None,
                  oid_size: int = 20) -> tuple[list[str], list[str]]:
    """(gitlinks, sparse directories) of an index file. Paths recorded as gitlinks (mode 160000) in the index file (`Repo.index`:
    `.git/index`, or `GIT_INDEX_FILE`), read by parsing it — never via `git`,
    which would read the config we judge.

    This is the criterion that matters: a nested repository is only dangerous
    once a gitlink references it, and the gitlink names it wherever it is.

    Every entry name is also checked as git's verify_path would (see
    `verify_path`): git writes a name from the index without that check. [55]

    `cache` (`<key>.idx` in the state dir, out of the container's reach)
    memoizes the result keyed by the file's sha256, one record per index
    file (the repository's, its submodules', its worktrees'): the Python
    parse costs ~40 ms for 96k entries (Linux kernel), the hash 4 ms. A
    modified — or forged — index has another sha256 and is re-parsed; an
    unreadable, inconsistent or older-version cache is ignored (a cache
    written before the name check would vouch for a forged index). Nothing
    is cached when the parser refuses.

    `oid_size`: bytes of an object id in the entries, from the repository's
    object format (`object_id_size`): 20 for SHA-1, 32 for SHA-256. A record
    without it was written for SHA-1 (a SHA-256 index was always refused,
    never cached). [63]

    Sparse directories: with a sparse index (`index.sparse`, the `sdir`
    extension) a directory outside the cone is one entry, mode 040000,
    naming a tree — whose gitlinks the parser cannot see (objects are not
    read). Returned for the caller to look on disk (`index_nested`). [87]"""
    p = index
    try:
        data = read_file(p)
    except OSError:
        return [], []
    if len(data) < 12 or data[:4] != b"DIRC":
        return [], []
    digest = hashlib.sha256(data).hexdigest()
    records: dict = {}
    if cache is not None:
        try:
            c = json.loads(cache.read_text())
            if (isinstance(c, dict) and c.get("v") == INDEX_CACHE_VERSION
                    and isinstance(c.get("indexes"), dict)):
                records = c["indexes"]
                hit = records.get(str(p))
                if (isinstance(hit, dict) and hit.get("sha256") == digest
                        and hit.get("oid", 20) == oid_size
                        and all(isinstance(hit.get(k), list)
                                and all(isinstance(x, str) for x in hit[k])
                                for k in ("gitlinks", "sparse"))):
                    return list(hit["gitlinks"]), list(hit["sparse"])
        except (OSError, ValueError):
            records = {}
    out, sparse = _parse_index_gitlinks(data, p, oid_size)
    if cache is not None:
        try:
            keep = {k: v for k, v in records.items()
                    if isinstance(k, str) and k != str(p) and os.path.exists(k)}
            keep[str(p)] = {"sha256": digest, "oid": oid_size, "gitlinks": out, "sparse": sparse}
            tmp = Path(str(cache) + ".tmp")
            tmp.write_text(json.dumps({"v": INDEX_CACHE_VERSION, "indexes": keep}))
            os.replace(tmp, cache)
        except OSError:
            pass
    return out, sparse


def index_nested(tree: Path, gitlinks: list[str], sparse: list[str]) -> set[Path]:
    """The nested `.git` an index points git to, under `tree`: at each
    gitlink, and anywhere inside a sparse directory that is on disk — git
    expands that entry into the tree's own entries, gitlinks included,
    once the directory exists (a sandbox writes the tree, a sparse index
    and the repository; `git status` then ran its fsmonitor). A sparse
    directory is normally absent from the disk: the walk costs nothing
    then. [87]"""
    out = set()
    for rel in gitlinks:
        g = tree / rel / ".git"
        if g.exists() or g.is_symlink():
            out.add(g)
    for rel in sparse:
        d = tree / rel
        if d.is_dir() and not d.is_symlink():
            for dirpath, dirnames, filenames in os.walk(d, onerror=_walk_error):
                if ".git" in dirnames or ".git" in filenames:
                    out.add(Path(dirpath) / ".git")
                dirnames[:] = [n for n in dirnames if n != ".git"]
    return out


# 3: sparse directories recorded [87]; 2: entry names checked by verify_path
# [55]; 1 (unversioned) never checked them.
INDEX_CACHE_VERSION = 3


# ------------------------------------------------- index entry names [55]
# Port of git's verify_path (read-cache.c) with core.protectHFS and
# core.protectNTFS both on: git refuses these names when it reads a tree
# into the index, `git add`s or `update-index`es them, but `checkout -- .`,
# `restore --worktree` and `checkout-index` write whatever the index holds.
# Both protections are applied on every platform (fail closed): git
# refuses the same names at `add` on macOS (HFS) and everywhere (NTFS,
# default since 2.24), so a legitimate index never holds them.
_HFS_IGNORED = {0x200c, 0x200d, 0x200e, 0x200f, 0x202a, 0x202b, 0x202c, 0x202d,
                0x202e, 0x206a, 0x206b, 0x206c, 0x206d, 0x206e, 0x206f, 0xfeff}


def _utf8_chars(b: bytes, i: int) -> Iterator[int | None]:
    """Code points from offset `i` as pick_one_utf8_char reads them: None
    on malformed UTF-8 (then nothing more), 0 at the end."""
    while i < len(b):
        c = b[i]
        n = 1 if c < 0x80 else 2 if c >> 5 == 6 else 3 if c >> 4 == 14 else 4 if c >> 3 == 30 else 0
        try:
            if not n:
                raise ValueError
            ch = b[i:i + n].decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            yield None
            return
        yield ord(ch)
        i += n
    yield 0


def _is_hfs_dot(b: bytes, i: int, needle: bytes) -> bool:
    """is_hfs_dot_generic: `.<needle>` ignoring the code points HFS+
    ignores, ASCII case-insensitive, then the end or `/`. Malformed UTF-8
    reads as the end (git's next_hfs_char returns 0)."""
    it = (c for c in _utf8_chars(b, i) if c not in _HFS_IGNORED)
    def nxt() -> int:
        c = next(it, 0)
        return 0 if c is None else c
    if nxt() != ord("."):
        return False
    for want in needle:
        c = nxt()
        if c > 127 or chr(c).lower() != chr(want):
            return False
    c = nxt()
    return c == 0 or c == ord("/")


def _is_ntfs_dotgit(b: bytes, i: int) -> bool:
    """is_ntfs_dotgit: `.git` or `git~1`, then only spaces and dots up to
    the end, a `/`, a `\\` or a `:` (an NTFS stream: `.git:x` is `.git`)."""
    r = b[i:]
    if r[:1] == b"." and r[1:4].lower() == b"git":
        j = 4
    elif r[:3].lower() == b"git" and r[3:5] == b"~1":
        j = 5
    else:
        return False
    for c in r[j:] + b"\0":
        if c in (0, 0x3A, 0x2F, 0x5C):
            return True
        if c not in (0x2E, 0x20):
            return False
    return True


def _is_ntfs_dot_generic(b: bytes, i: int, name: bytes, short: bytes) -> bool:
    """is_ntfs_dot_generic (used for `.gitmodules`): the long name, its
    `xxxxxx~1..4` short form, or the hashed fall-back short name, then only
    spaces and dots up to the end or a `:`."""
    r = b[i:] + b"\0"
    def rest_ok(j: int) -> bool:
        for c in r[j:]:
            if c in (0, 0x3A):
                return True
            if c not in (0x20, 0x2E):
                return False
        return True
    if r[:1] == b"." and r[1:1 + len(name)].lower() == name:
        return rest_ok(len(name) + 1)
    if r[:6].lower() == name[:6] and r[6:7] == b"~" and b"1" <= r[7:8] <= b"4":
        return rest_ok(8)
    k, saw_tilde = 0, False
    while k < 8:
        c = r[k]
        if c == 0:
            return False
        if saw_tilde:
            if not 0x30 <= c <= 0x39:
                return False
        elif c == 0x7E:
            k += 1
            if not 0x31 <= r[k] <= 0x39:
                return False
            saw_tilde = True
        elif k >= 6 or c & 0x80 or chr(c).lower() != chr(short[k]):
            return False
        k += 1
    return rest_ok(8)


def _verify_dotfile(b: bytes, i: int, mode: int) -> bool:
    """verify_dotfile: `b[i]` follows a `.` that starts a component."""
    r = b[i:i + 4]
    if i >= len(b) or b[i] == 0x2F:
        return False                                   # "."
    if r[:1] in (b"g", b"G") and r[1:3].lower() == b"it":
        if i + 3 >= len(b) or b[i + 3] == 0x2F:
            return False                               # ".git"
        if mode & 0xF000 == 0xA000:
            tail = b[i + 3:]
            if tail[:7].lower() == b"modules" and (len(tail) == 7 or tail[7] == 0x2F):
                return False                           # symlink ".gitmodules"
    elif r[:1] == b".":
        if i + 1 >= len(b) or b[i + 1] == 0x2F:
            return False                               # ".."
    return True


# A name that can be refused contains one of these: an empty, `.` or `..`
# component (or is empty, or starts/ends with `/`), a `\\`, a non-ASCII
# byte (HFS ignorables, malformed UTF-8), `.git`, `git~`, or the `.gitmodules`
# short names. Anything else is accepted without the full walk (the port
# costs ~3.5 µs per name). The parity test runs both paths against git.
_SUSPECT = re.compile(rb"(?:^|/)\.{0,2}(?:/|$)|[\\\x80-\xff]|\.git|git~|gitmod|gi7eb", re.I)
# The same over every name of an index at once, NUL-separated (a name never
# holds a NUL: the parser refuses it): plain substring searches (memmem, C)
# on the lower-cased buffer, then the port only on the names they point at.
# Every refusable name has a component that is empty, or starts with `.`
# (`.git` and the HFS forms), or holds a `\\` (NTFS separator), `git~`
# (`git~1`), the `.gitmodules` short names or a non-ASCII byte. Kernel-sized
# index (96k names, 2.6 MB joined): ~30 ms once, then cached by sha256; a
# regex over the buffer cost 40 ms, the port on every name 340 ms.
_SUSPECT_SUBSTRINGS = [b"\0\0", b"\0/", b"/\0", b"//", b"\0.", b"/.",
                       b"\\", b"git~", b"gitmod", b"gi7eb"]


def forged_entry(entries: list[tuple[bytes, int]]) -> bytes | None:
    """The first (name, mode) of an index that verify_path refuses, else None."""
    buf = (b"\0" + b"\0".join(n for n, _ in entries) + b"\0").lower()
    hits: set[int] = set()
    for pat in _SUSPECT_SUBSTRINGS:
        off = buf.find(pat)
        while off != -1:
            hits.update((off, off + len(pat) - 1))      # a hit may straddle a NUL
            off = buf.find(pat, off + 1)
    if not buf.isascii():
        hits.update(m.start() for m in re.finditer(rb"[\x80-\xff]", buf))
    nuls, last, done = 0, 0, -1       # NULs before `off`: `off` is inside entries[nuls - 1]
    for off in sorted(hits):
        nuls += buf.count(b"\0", last, off)
        last = off
        # On the separator itself (`\0\0`, `\0/`…): the name that follows it.
        i = nuls if buf[off] == 0 else nuls - 1
        if i == done or i >= len(entries):
            continue
        done = i
        name, mode = entries[i]
        if not verify_path(name, mode):
            return name
    return None


def verify_path(b: bytes, mode: int) -> bool:
    """git's verify_path(path, mode), protectHFS and protectNTFS on. A
    terminating `/` is allowed only for a sparse directory entry."""
    if not _SUSPECT.search(b):
        return True
    link = mode & 0xF000 == 0xA000
    i = 0
    while True:
        # start of a component (`inside:` in git)
        if _is_hfs_dot(b, i, b"git") or _is_ntfs_dotgit(b, i):
            return False
        if link and (_is_hfs_dot(b, i, b"gitmodules")
                     or _is_ntfs_dot_generic(b, i, b"gitmodules", b"gi7eba")):
            return False
        if i >= len(b):
            return mode & 0xF000 == 0x4000             # empty name / trailing "/"
        c = b[i]
        i += 1
        if (c == 0x2E and not _verify_dotfile(b, i, mode)) or c == 0x2F:
            return False
        while True:
            if i >= len(b):
                return True
            c = b[i]
            i += 1
            if c == 0x2F:
                break
            if c == 0x5C:                              # "\\": NTFS separator
                if _is_ntfs_dotgit(b, i):
                    return False
                if link and _is_ntfs_dot_generic(b, i, b"gitmodules", b"gi7eba"):
                    return False


def forged_index_hint(p: Path, name: bytes) -> str:
    return (f"forged git index: entry {name.decode(errors='replace')!r} in {p} escapes the "
            f"work tree — `git checkout -- .` or `git restore` would write it as is (into "
            f"the gitdir, outside the repository or at an absolute path) and can run it as a "
            f"hook. git never writes such an entry itself. Rebuild the index from the "
            f"commits, which git validates: `rm {p}` then `git reset -q` in that repository "
            f"or worktree (staged changes are lost); then look at what else the sandbox "
            f"left. [55]")


# core.repositoryformatversion as git_parse_signed reads it: strtoimax with
# base 0 (`0x1`, `01`), then an optional unit; anything else makes git die.
_GIT_INT = re.compile(r"[ \t\n\v\f\r]*([+-]?)(0[xX][0-9a-fA-F]+|0[0-7]*|[1-9][0-9]*)([kKmMgG]?)")


def object_id_size(gitdir: Path) -> int:
    """Bytes of an object id in the indexes of the repository whose config
    is `gitdir/config` (the common dir; a submodule's own gitdir). As git's
    check_repository_format reads it, checked against git 2.50 and 2.47:
    only that file (no include, no config.worktree), the last value wins;
    no `core.repositoryformatversion` (or -1, git's "unset") → the
    extension is ignored, SHA-1; another negative version keeps it;
    version 0 with `extensions.objectFormat`, a version above 1 → git dies.
    A value other than exactly `sha1`/`sha256`, wherever it stands and
    whatever the version, makes git die as it reads it (handle_extension):
    refused too. [63]"""
    version = fmt = None
    cfg = gitdir / "config"
    if not cfg.is_file():
        return 20
    for section, key, value in parse_git_config(cfg):
        if section == "core" and key == "repositoryformatversion":
            version = value
        elif section == "extensions" and key == "objectformat":
            if value not in ("sha1", "sha256"):
                raise Refuse(f"unknown extensions.objectFormat {value!r} in {cfg}: git refuses it too")
            fmt = value
    if version is None:
        return 20
    m = _GIT_INT.fullmatch(version)
    if m is None:
        raise Refuse(f"bad core.repositoryformatversion {version!r} in {cfg}: git refuses it too")
    sign, digits, unit = m.groups()
    n = int(digits, 16 if digits[:2] in ("0x", "0X") else 8 if digits.startswith("0") else 10)
    n *= {"": 1, "k": 1 << 10, "m": 1 << 20, "g": 1 << 30}[unit.lower()]
    if sign == "-":
        n = -n
    if n == -1:
        return 20                 # git's "unset": read_repository_format clears the format
    if n > 1 or (n == 0 and fmt is not None):
        raise Refuse(f"unsupported repository format (core.repositoryformatversion = "
                     f"{version!r}{', extensions.objectFormat' if fmt is not None else ''}) "
                     f"in {cfg}: git refuses it too")
    return 32 if fmt == "sha256" else 20


def _parse_index_gitlinks(data: bytes, p: Path, oid_size: int = 20) -> tuple[list[str], list[str]]:
    # Fixed part of an entry: ctime, mtime, dev, ino, mode, uid, gid, size
    # (40 bytes), the object id (20 or 32), the flags (2). It was fixed at 62:
    # every SHA-256 index was refused as forged. [63]
    fixed = 40 + oid_size + 2
    version = int.from_bytes(data[4:8], "big")
    count = int.from_bytes(data[8:12], "big")
    if version not in (2, 3, 4):
        raise Refuse(f"unsupported git index version ({version}): cannot check "
                     f"nested repositories of {p}")
    out, sparse, off, prev = [], [], 12, b""
    entries: list[tuple[bytes, int]] = []
    for _ in range(count):
        if off + fixed > len(data):
            break
        mode = int.from_bytes(data[off + 24:off + 28], "big")
        flags = int.from_bytes(data[off + fixed - 2:off + fixed], "big")
        cur = off + fixed
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
        entries.append((name, mode))
        if mode & 0xF000 == 0xE000:      # 0160000: gitlink
            out.append(name.decode(errors="surrogateescape"))
        elif mode & 0xF000 == 0x4000:    # 040000: a sparse directory [87]
            sparse.append(name.decode(errors="surrogateescape"))
    # The extensions first: a split index stores its replaced entries with
    # an empty name, which forged_entry took for a forged one.
    _check_index_extensions(data, off, p, oid_size)
    bad = forged_entry(entries)
    if bad is not None:
        raise Refuse(forged_index_hint(p, bad))
    return out, sparse


# Index extensions whose signature starts with a lowercase letter are
# required: git dies on one it does not know (read_index_extension: "index
# uses %.4s extension, which we do not understand"), because they change
# what the entries mean. The same rule here, so that a future one is a
# refusal, not a blind spot: `sdir` (sparse directories, read above) and
# `link` (split index: the entries live in a sharedindex file, check_split_index).
KNOWN_REQUIRED_EXTENSIONS = {b"sdir"}


def _check_index_extensions(data: bytes, off: int, p: Path, oid_size: int) -> None:
    """Walk the extensions after the entries (signature, 32-bit size, data),
    up to the trailing checksum. [87]"""
    end = len(data) - oid_size
    while off + 8 <= end:
        sig, size = data[off:off + 4], int.from_bytes(data[off + 4:off + 8], "big")
        if not b"A"[0] <= sig[0] <= b"Z"[0] and sig not in KNOWN_REQUIRED_EXTENSIONS:
            if sig == b"link":
                raise Refuse(f"core.splitIndex not supported ({p} is a split index): run "
                             f"`git update-index --no-split-index` and retry")
            raise Refuse(f"{p}: index extension {sig!r} gitguard does not know; git "
                         f"requires it to read the entries (a newer git?), so their "
                         f"gitlinks cannot be checked")
        off += 8 + size


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


def _read_todo(p: Path) -> None:
    """Rebase/cherry-pick todo lists accept `exec <cmd>` lines that git runs
    verbatim. The container can inject some during an in-progress rebase:
    refuse their presence, unless the user runs `--exec` rebases themselves."""
    for line in read_file(p).decode(errors="surrogateescape").splitlines():
        # git accepts any blank after the command word (`exec<TAB>cmd`). [35]
        word = (line.split(None, 1) or [""])[0]
        if word in ("exec", "x"):
            raise Refuse(
                f"`exec` line in {p}: git would run it on the next "
                f"`rebase --continue`. Check this file; if this rebase is really "
                f"yours, retry with GITGUARD_ALLOW_REBASE_EXEC=1.")


def _read_strategy_file(p: Path) -> None:
    """`rebase-merge/strategy`: the merge strategy name of an interrupted
    interactive/merge rebase. On `rebase --continue` git passes it straight to
    the merge machinery, which, for a name it does not know as a builtin,
    execs `git-merge-<name>` from the exec-path/PATH — without the "available
    strategies" validation a plain `git merge -s <name>` applies. [51]
    Exactly as git reads it (read_oneliner): only ONE trailing newline is
    trimmed. No strip(): `ort\t` is not `ort`, git execs `git-merge-ort<TAB>`.
    Bytes, not read_text(): universal newlines would turn a lone CR (`ort\r`,
    a different name for git) into the newline we trim."""
    name = read_file(p).decode(errors="surrogateescape")
    if name.endswith("\n"):          # strbuf_trim_trailing_newline
        name = name[:-1]
        if name.endswith("\r"):
            name = name[:-1]
    _check_strategy(p, name)


def _read_sequencer_opts(p: Path) -> None:
    """cherry-pick/revert keep their strategy in a config-format file,
    `[options] strategy`. [51]"""
    for sect, key, value in parse_git_config(p):
        if sect == "options" and key == "strategy":
            _check_strategy(p, value)


# Volatile files git reads back as instructions, relative to a gitdir root,
# each with the reader that refuses what would run. Checked under every
# root, submodules and linked worktrees included: `submodule foreach 'git
# rebase --continue'` runs an unwrapped git there. [36]
VOLATILE_READERS = {
    "rebase-merge/git-rebase-todo": _read_todo,
    "rebase-apply/git-rebase-todo": _read_todo,
    "sequencer/todo": _read_todo,
    "rebase-merge/strategy": _read_strategy_file,
    "sequencer/opts": _read_sequencer_opts,
}


def check_volatile_readers(repo: Repo) -> None:
    """Each file of VOLATILE_READERS present under any gitdir root, read by
    its reader; GITGUARD_ALLOW_REBASE_EXEC skips them all (the user's own
    `--exec` rebase or custom strategy)."""
    if os.environ.get("GITGUARD_ALLOW_REBASE_EXEC"):
        return
    roots = dict.fromkeys([*gitdir_roots(repo.gitdir), *gitdir_roots(repo.common)])
    for r in roots:
        for rel, read in VOLATILE_READERS.items():
            p = r / rel
            if is_file(p):
                read(p)


def _check_strategy(p: Path, name: str) -> None:
    """Refuse a merge strategy name that is not one of git's builtins: for any
    other, git execs `git-merge-<name>` — from PATH or the exec-path, and since
    the name may contain a `/`, relative to the cwd, i.e. a script of the work
    tree. An empty name is no exception: git execs `git-merge-` (checked). [51]"""
    if name not in BUILTIN_MERGE_STRATEGIES:
        raise Refuse(
            f"non-builtin merge strategy {name!r} in {p}: git would exec "
            f"`git-merge-{name}` on the next `--continue`. Check "
            f"this file; if this operation is really yours, retry with "
            f"GITGUARD_ALLOW_REBASE_EXEC=1.")


def check_indexes(repo: Repo) -> None:
    """The entry names of every index git may check files out from: the
    submodules' (`modules/<x>/index`: `submodule update`, `--recurse-
    submodules` or `submodule foreach` run an unwrapped git there) and the
    other worktrees' (`worktrees/<x>/index`, and the main one seen from a
    linked worktree). The repository's own index (`Repo.index`) is read by
    `Repo.gitfiles`. Same parser and cache: a few small files. [55]

    A submodule's gitlinks and `.gitmodules` name nested repositories of its
    tree, which get the rule of the superproject's (check_nested_git) with
    the submodule's gitdir as the root they must point under. They were
    parsed and dropped: `git status` in the superproject recurses into the
    submodule, then into a nested repository its index names, and runs that
    repository's core.fsmonitor. [60] A linked worktree's gitlinks are not
    followed: nothing recurses into another worktree, and git run there is
    checked there."""
    cache = Path(str(repo.key) + ".idx")
    trees = dict(submodule_trees(repo))
    roots = set(dict.fromkeys([*gitdir_roots(repo.gitdir), *gitdir_roots(repo.common)]))
    for r in sorted(roots):
        if r == repo.gitdir:
            continue
        # The object format of the repository this index belongs to: a
        # linked worktree's (`worktrees/<x>`, of the main repository or of a
        # submodule) is in the gitdir its `commondir` names, a submodule's in
        # its own `modules/<x>/config`.
        cd = r / "commondir"
        fmt_dir = _resolve_existing(r / _read_path_file(cd), cd) if cd.is_file() else r
        links = index_entries(r / "index", cache, object_id_size(fmt_dir))
        tree = trees.get(r)
        if tree is None:
            continue
        nested = set(gitmodules_gits(tree)) | index_nested(tree, *links)
        for n in sorted(nested):
            check_nested_git(n, r, roots)


def check_nested_git(n: Path, common: Path, roots: set[Path]) -> None:
    """A nested `.git` — declared in .gitmodules or referenced by an index
    gitlink, wherever it is (node_modules/, build/…) — must be a file pointing
    to a gitdir root under `common` (`roots`: gitdir_roots of the whole
    repository): a submodule's `modules/<x>`, a linked worktree's
    `worktrees/<x>` stored inside the tree (`.worktrees/x`). "Anywhere under
    modules/" accepted `modules/x/refs/p`, a volatile zone of a real
    submodule's gitdir, where a planted gitdir is hashed by nobody. [103]"""
    if n.is_symlink():
        raise Refuse(f"nested .git is a symlink: {n}")
    if n.is_dir():
        # Declared in .gitmodules or not: a nested .git directory is never
        # a real submodule (that one has a .git file pointing under
        # .git/modules), and git reads its config as soon as a gitlink
        # references it in the index.
        raise Refuse(nested_repo_hint(n))
    target = read_gitfile(n)
    if target not in roots or common not in target.parents:
        raise Refuse(f"{n} points to no gitdir under {common}/modules or {common}/worktrees: {target}")


def check_structure(repo: Repo, refs: list[tuple[str, Path]]) -> None:
    check_split_index(repo)
    check_indexes(repo)
    roots = set(gitdir_roots(repo.common))
    for n in repo.gitfiles:
        check_nested_git(n, repo.common, roots)
    check_volatile_readers(repo)
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
        for p in walk_all(root, repo):
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


def walk_all(base: Path, repo: Repo | None = None) -> Iterator[Path]:
    """What a path named by the config holds for git: the file or symlink
    itself, or for a directory (DIR_KEYS, a local remote's hooks/) its files
    and symlinks at any depth — a hook sources `lib/common.sh` next to it —
    **except when the directory contains the repository** (`core.hooksPath
    = ..`, `~`): there git runs `<hooksPath>/<hook>` and nothing of the
    tree, so depth 1. Walked recursively, such a directory fingerprinted the
    whole volume (the work tree, the gitdir without its volatile exclusions,
    gitguard's own state: every commit, then every `trust`, alerted). The
    state directory is never entered (a template directory adds its `hooks/`
    as a ref of its own, config_refs). [65]"""
    if base.is_symlink() or base.is_file():
        yield base
        return
    state = STATE.resolve()
    def inside(p: Path, d: Path) -> bool:
        return p == d or d in p.parents
    if inside(base, state):
        return                             # add() refuses it first; belt and braces
    if repo is not None and any(inside(t, base) for t in (repo.root, repo.gitdir, repo.common)):
        try:
            children = sorted(base.iterdir())
        except FileNotFoundError:
            return
        except OSError as e:
            _walk_error(e)
            return
        for c in children:
            if c.is_symlink() or not c.is_dir():
                yield c
        return
    for dirpath, dirnames, filenames in os.walk(base, onerror=_walk_error):
        d = Path(dirpath)
        keep = []
        for name in dirnames:
            if (d / name).is_symlink():
                yield d / name
            elif not inside(d / name, state):
                keep.append(name)
        dirnames[:] = keep
        for name in filenames:
            yield d / name


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


def iter_global_config() -> Iterator[tuple[Path, str, str, str]]:
    """(file, section, key, value) of the system and global config files
    and of the files they include, in git's reading order: INCLUDE_DEPTH
    levels of `include.path` / `includeIf.*.path`, each relative to the
    including file, the conditions not evaluated (a superset, as in
    config_refs). For a reader of one global setting; config_refs keeps its
    own walk, which carries a base and a scope per file and watches the
    include targets. [85]"""
    queue, seen = list(global_config_files()), set()
    for _ in range(INCLUDE_DEPTH + 1):
        nxt = []
        for f in queue:
            if f in seen or not is_file(f):
                continue
            seen.add(f)
            for section, key, value in parse_git_config(f):
                yield f, section, key, value
                if section.startswith("include") and key == "path":
                    nxt.append(_expand2(value, f.parent)[0])     # as opened [94]
        queue = nxt


SAFE_BARE_HINT = ("`git config --global safe.bareRepository explicit`: git then refuses "
                  "to discover a bare gitdir planted in a subdirectory [23], even from a "
                  "tool that does not go through gitguard")


def safe_bare_explicit() -> bool:
    """`safe.bareRepository = explicit` in the system or global config or a
    file they include ([85]), read with our parser (never `git config`,
    which would honour the judged config). Last value wins, as for git."""
    value = None
    for _, section, key, v in iter_global_config():
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


class ConfigScan:
    """What the configuration git will read says about one repository,
    gathered in a single pass over every config source (`run`):

    - `refs`: paths outside the gitdir that the config makes git execute or
      read — core.hooksPath, include.path (recursive), any token of a value
      that exists as a path — as [(scope, path)], scope 'wt' (under the
      root) or 'ext' (elsewhere, writable); plus the tree files that drive
      git: root gitfile, .gitmodules, each submodule's gitfile.
    - `remote_names`: every remote the repository's config defines (not a
      remote's own config) that has a url: what `git push <name>` resolves
      through config. A `[remote "x"]` section without one (a global
      `remote.origin.prune`) is not a remote for git: `push x` takes `x` as
      a path. [62] [82]
    The `-c` an alias carries is config like any other: what it names is
    watched. [80] Two steps: `consider` reads one (section, key, value) and
    `add` records one path. The sources and the order are in `run`.
    Formerly one 240-line function with two closures; the fixes of [39],
    [45], [48], [56], [59], [61], [62], [65]–[68], [73], [75], [79], [80]
    and [82] each live in a branch of `consider` or `add`."""

    def __init__(self, repo: Repo) -> None:
        self.repo = repo
        self.out: dict[Path, str] = {}
        self.refs: list[tuple[str, Path]] = []
        self.remote_names: set[str] = set()
        # Values of global origin and of the environment / `-c` (an alias's
        # `-c` included): resolved again against each local remote and
        # submodule. [68] [92]
        self.global_vals: list[tuple[str, str, str]] = []
        self.env_vals: list[tuple[str, str, str]] = []
        self.remote_bases: set[Path] = set()
        self.nxt: list[tuple[Path, Path, bool, bool]] = []    # config files found while reading
        self.tokens_seen: set[tuple[str, Path]] = set()

    def add(self, literal: Path, p: Path, allow_dir: bool = False) -> None:
        """Record `p` (canonical; `literal` as the config spelt it) as a path
        git may execute or read, or refuse it."""
        repo, out = self.repo, self.out
        if not (p.exists() or p.is_symlink()):
            return
        try:
            mode = p.stat().st_mode
        except OSError:
            mode = 0
        if p.exists() and not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
            # A device, a FIFO, a socket: `/dev/null` in an alias
            # (`!git status >/dev/null`) was taken for a path to watch and
            # refused as an unreadable directory, every repository at once
            # when the alias was global, `trust` included. Nothing git runs
            # or reads as a file. [109]
            return
        # git executes files. A directory is only loaded by the keys that read
        # its content (DIR_KEYS); elsewhere it is a program argument
        # (`safe.directory = ~/projects`, `remote.origin.url = /local/repo`,
        # `!make -C src`) and fingerprinting it alerted on every neighbouring
        # file — and `restore` deleted there. [25]
        if p.is_dir() and not allow_dir:
            return
        # The config naming gitguard's own state: the reference would watch
        # itself (every `trust` rewrites it). Structurally abnormal. [65]
        state = STATE.resolve()
        if any(q == state or state in q.parents for q in (p, literal)):
            raise Refuse(f"path referenced by the config lies in gitguard's state "
                         f"directory ({state}): {literal}")
        # A referenced path reached through a symlink in the tree is refused:
        # resolving the link would pull its target (e.g. $HOME) into the
        # fingerprint, and `restore` would delete "what was added" over there.
        # The link's own location decides, not its spelling (`/tmp/x/h` for
        # `/private/tmp/x/h` on macOS, an aliased directory).
        in_tree = lambda q: repo.root in q.parents or q == repo.root
        link = literal.is_symlink()
        if (link and in_tree(literal.parent.resolve() / literal.name)) or any(
                q.is_symlink() for q in literal.parents if in_tree(q)):
            raise Refuse(f"path referenced by the config reached through a symlink: {literal}")
        # Outside the tree a symlink is ordinary (Homebrew's
        # `/opt/homebrew/bin/gpg`, Debian's `/usr/bin/vim` alternative, a
        # stow-managed `~/.gitconfig.local`): refused, it blocked every
        # repository, `trust` included. The link itself is watched when it
        # can be replaced: its hash holds its target string and the content
        # git runs, so repointing it is seen (the canonical path below alone
        # would keep hashing the old target). `restore` never acts outside
        # the repository. A link to a directory stays refused (_hash_file):
        # its content would escape the fingerprint. [75]
        if link and literal != p and _replaceable(literal):
            if p.is_dir():
                raise Refuse(f"path referenced by the config is a symlink to a "
                             f"directory: {literal}")
            out[literal] = "ext"
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

    def consider(self, section: str, key: str, value: str, base: Path, cfdir: Path | None,
                 remotes: bool, glob: bool = False, relocated: bool = False) -> None:
        """One config entry. `base`: the directory its relative values resolve
        against (the root, a submodule's tree, a remote's gitdir); `cfdir`:
        the directory of the file it comes from (None: environment or
        command line); `remotes`: follow the remotes it names; `glob`: the
        entry is of global origin (system, global, XDG, their includes);
        `relocated`: a global or `-c` value read again against another base
        than the root (run)."""
        repo = self.repo
        # `git push <name>` resolves <name> through the repository's config
        # (local, global, environment: those whose base is the root), not a
        # submodule's: there, `<name>` is a path.
        if base == repo.root and section.startswith("remote.") and key in ("url", "pushurl"):
            self.remote_names.add(section[len("remote."):])
        # `[alias] ci = …`, or since git 2.54 `[alias "ci"] command = …`: the
        # subsection form was read as an unknown section, its `-c` never
        # seen. [90]
        alias = key if section == "alias" else (
            section[len("alias."):] if section.startswith("alias.") and key == "command" else None)
        if alias is not None:
            _, pairs = _alias_parts(value)
            # `alias.ci = -c core.hooksPath=.githooks commit`: git applies the
            # alias's `-c` when it runs, so `.githooks` is a hooks directory
            # like one named on the command line — and travels like it:
            # to a submodule (GIT_CONFIG_PARAMETERS kept), not to a local
            # receive-pack (cleared), whichever file defines the alias. [80]
            for k, v in pairs:
                sk = _split_config_key(k)
                if sk is not None:
                    val = "true" if v is None else v
                    if base == repo.root:
                        self.env_vals.append((*sk, val))
                    self.consider(*sk, val, base, None, remotes, False, relocated)
        if glob and alias is None:
            self.global_vals.append((section, key, value))
        if (section, key) in DIR_KEYS:
            # `:(optional)<path>` (git 2.52, a pathname value): the path,
            # the variable unset when it does not exist. Exactly that prefix,
            # once (`:(Optional)` is a path). Not for include.path, which
            # git opens as written. [91]
            if value.startswith(OPTIONAL_PREFIX):
                value = value[len(OPTIONAL_PREFIX):]
            literal, p = _expand2(value, base)
            if p == repo.root:
                # A hooks directory at the root of the tree: every top-level
                # file is a hook git runs, and add() drops the root (it is
                # not fingerprinted as a whole). `.` and `./` included: git
                # then searches the PATH, a broken setup anyway. [59]
                raise Refuse(f"{section}.{key} = {value!r} resolves to the root of the "
                             f"work tree ({p}): every file at the top of the tree would be "
                             f"a hook, gitguard cannot watch that. Move the hooks to a "
                             f"subdirectory (e.g. `.githooks`, then `git config "
                             f"{section}.{key} .githooks`) and retry.")
            self.add(literal, p, allow_dir=True)
            if key == "templatedir":
                # git copies the whole template; what it can run is hooks/.
                # Named on its own: still watched if the template directory
                # contains the repository (then walked at depth 1). [65]
                self.add(literal / "hooks", p / "hooks", allow_dir=True)
        elif section.startswith("include") and key == "path":
            # Relative to the including file; from the command line or the
            # environment git only accepts an absolute path ("relative config
            # includes must come from files").
            if cfdir is None and not _expand2(value, Path("/"))[0].is_absolute():
                return
            # Queued as git opens it, not canonical: an include inside it is
            # relative to that path's directory — a symlink's, not its
            # target's. [94]
            literal, p = _expand2(value, cfdir or base)
            if is_file(p):
                self.nxt.append((literal, base, remotes, glob))
            self.add(literal, p)
        elif remotes and ((section.startswith("remote.") and key in ("url", "pushurl"))
                          or (section == "remote" and key == "pushdefault")
                          or (section.startswith("branch.") and key in ("remote", "pushremote"))):
            # A local remote: `push` runs its hooks and honours its
            # config (hooksPath…). Only those, never the whole
            # directory ([25]): its config and its hooks/ [45], from the
            # common dir git opens, the gitfile and `commondir` that lead
            # there, and config.worktree (read with extensions.worktreeConfig;
            # watched and parsed in any case, a superset). [61]
            # remote.pushDefault, branch.<b>.pushRemote and branch.<b>.remote
            # name a remote, but a name no `remote.<name>` section defines is
            # taken as a URL: `git push` with no argument went there,
            # unwatched. A defined name is also tried as a path (a superset:
            # `<root>/origin` is rarely a repository). [73]
            r = _local_remote(value, base)
            if r is not None:
                gd, common, rbase, files = r
                self.remote_bases.add(rbase)
                for f in files:
                    self.add(f, f)
                for f in (common / "config", gd / "config.worktree"):
                    self.add(f, f)
                    self.nxt.append((f, rbase, False, False))
                self.add(common / "hooks", common / "hooks", allow_dir=True)
        elif _data_key(section, key):
            return                       # a file read as data, never run [56]
        else:
            for tok in _glued_values(_value_tokens(value)):
                # Read again against a submodule or a remote, a token is a
                # candidate only as an explicit relative path (`./x`,
                # `scripts/x`): a bare word is run from the PATH, an absolute
                # path was seen at the root, and every word of the global
                # config (`user.name = t`) matched a file of each submodule. [92]
                if relocated and ("/" not in tok or tok.startswith(("/", "~"))):
                    continue
                # The same token comes back from value to value (aliases
                # share their words): each one costs a resolve(). Once per
                # base is enough, add() is idempotent.
                if (tok and tok not in (".", "..") and not tok.startswith("-")
                        and (tok, base) not in self.tokens_seen):
                    self.tokens_seen.add((tok, base))
                    self.add(*_expand2(tok, base))

    def run(self) -> "ConfigScan":
        """Read every source in git's order and fill `refs`, `remote_names`
        and `cmd`."""
        repo, out = self.repo, self.out
        # .lfsconfig: git-lfs reads lfs.customtransfer.*.path from it (a program it runs). [34]
        # The gitfile sits next to the tree git was entered from, which
        # core.worktree may have moved elsewhere (a linked worktree with
        # extensions.worktreeConfig): then it is outside the root, scope ext. [76]
        for special in [repo.label / ".git", repo.root / ".gitmodules",
                        repo.root / ".lfsconfig"]:
            if special.is_file():
                out[special] = "wt" if repo.root in special.parents else "ext"
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
        # Fourth element: the file is of global origin (system, global, XDG and
        # their includes). Git reads those in every repository it enters, so a
        # relative DIR_KEYS value of theirs (`core.hooksPath = .githooks`) is
        # resolved again against every other base below — a local remote's gitdir
        # (receive-pack ran `hub.git/.githooks/pre-receive`), a submodule's tree
        # (`submodule update` ran `sub/.githooks/post-checkout`) — where it was
        # resolved against the root only. Values from the environment and `-c`
        # reach a submodule (prepare_submodule_repo_env keeps
        # GIT_CONFIG_PARAMETERS) but not a local receive-pack (local_repo_env
        # clears it), checked on git 2.47 and 2.50. [68]
        queue = [(f, repo.root, True, False) for f in (repo.gitdir / "config",
                                                       repo.gitdir / "config.worktree",
                                                       repo.common / "config",
                                                       repo.common / "config.worktree")]
        queue += [(f, repo.root, True, True) for f in global_config_files()]
        sub_configs = _submodule_configs(repo)
        queue += [(f, b, True, False) for f, b in sub_configs]
        sub_bases = {b for _, b in sub_configs}
        # A file is read once per (file, base, origin), not once: one file
        # included by the superproject's config and a submodule's (a
        # `~/team.gitconfig`) has its relative values resolved in each; one
        # included by the local and the global config keeps its global
        # origin. [93]
        seen: set[tuple[Path, Path, bool]] = set()

        # Config git takes from its environment and command line (GIT_CONFIG_*,
        # `-c`): not writable by the sandbox, but its values may name paths in
        # the volume, which git honours like any other. [48]
        for section, key, value in env_config():
            self.env_vals.append((section, key, value))
            self.consider(section, key, value, repo.root, None, True)
        # +1: the first round consumes the base files; git then follows
        # INCLUDE_DEPTH levels of includes. With range(INCLUDE_DEPTH) the 10th
        # level was hashed but never parsed. [17]
        for _ in range(INCLUDE_DEPTH + 1):
            for cf, base, remotes, glob in queue:
                if (cf.resolve(), base, glob) in seen or not is_file(cf):
                    continue
                seen.add((cf.resolve(), base, glob))
                for section, key, value in parse_git_config(cf):
                    self.consider(section, key, value, base, cf.parent, remotes, glob)
            queue, self.nxt = self.nxt, []
        # The global values, resolved where git will resolve them next: in
        # each local remote (push) and each submodule; the environment's in
        # the submodules only. [68] Every key, not DIR_KEYS alone: a global
        # `hook.<n>.command = ./scripts/pc.sh` (git 2.54) runs
        # `sub/scripts/pc.sh` during `submodule update`. [92] Aliases are
        # not: git runs one where the user types it, and a git run from a
        # submodule is checked with that submodule as its root.
        for base in self.remote_bases - {repo.root}:
            for section, key, value in self.global_vals:
                self.consider(section, key, value, base, None, False, relocated=True)
        for base in sub_bases - {repo.root}:
            for section, key, value in [*self.global_vals, *self.env_vals]:
                self.consider(section, key, value, base, None, False, relocated=True)
        self.refs = sorted(((scope, p) for p, scope in out.items()), key=lambda t: str(t[1]))
        return self


def config_refs(repo: Repo) -> ConfigScan:
    """Read every config source of `repo` once: see ConfigScan."""
    return ConfigScan(repo).run()


def _replaceable(p: Path) -> bool:
    """Can the user — hence a container running as the user on a mounted
    volume — rewrite `p` or replace it? A 0555 script in a writable directory
    is unlinked and recreated: testing the file alone ignored it. [38]
    (Cost: a read-only file under a user-owned tree, e.g. a Homebrew binary
    named by absolute path in gpg.program, is now hashed: ~1 ms per MB.)"""
    return os.access(p, os.W_OK) or any(os.access(q, os.W_OK) for q in p.parents)


def _local_remote(url: str, base: Path) -> tuple[Path, Path, Path, list[Path]] | None:
    """(gitdir, common dir, base for its relative values, files that redirect
    it) if the remote URL designates a local repository (path or file://),
    else None. Like git: a `host:path` without a `/` before the colon is ssh.
    Opened as receive-pack opens it, a port of enter_repo (path.c, strict
    off): `<p>/.git`, `<p>`, `<p>.git/.git`, `<p>.git`, the first that is a
    regular file (a gitfile) or a directory is_git_directory accepts; the
    gitfile followed, then the gitdir's `commondir`, without the environment
    (git clears it for the transport child). The former reading took
    `<p>/.git` or a bare `<p>` and watched their config and hooks/: a
    planted `commondir`, a gitfile remote (`init --separate-git-dir`) moved
    the config and hooks git runs elsewhere. [61] A regular file that is no
    gitfile (a bundle) is not a repository: git dies on a push there.
    A URL is read as parse_connect_url (connect.c) reads it: percent-decoded
    whole (url_decode: `My%20Repos`, `%2F`, once, `%00` kept), split at the
    first `://`, the scheme must be `file`, the host part dropped up to the
    first `/` after a `[…]` (`file://host/p`, `file://[a/b]/p` reach `/p`).
    The encoded text named no directory: the remote went unwatched and
    `push` unchecked. [69] The base of the remote's relative values is its
    gitdir: enter_repo chdirs there and receive-pack runs the hooks from
    there (a non-bare remote with `core.hooksPath = .husky/_` runs
    `<remote>/.git/.husky/_/pre-receive`, not `<remote>/.husky/_`). [67]"""
    v = _url_decode(url) if _IS_URL.match(url) else url
    scheme, sep, host = v.partition("://")
    if sep:
        if scheme != "file":
            return None                   # git, ssh, http…: not a local repository
        start = host.find("@[") + 1 if "@[" in host else 0
        end = host.find("]", start + 1) + 1 if host[start:start + 1] == "[" else 0
        slash = host.find("/", end if end > 0 else 0)
        if slash == -1:
            return None                   # "no path specified": git dies
        v = host[slash:]
    elif ":" in v.split("/", 1)[0] and not v.startswith(("/", ".", "~")):
        return None                       # url_is_local_not_ssh: a colon before any slash is ssh
    p = _expand2(v, base)[1]
    dotgit = p.with_name(p.name + ".git")
    for cand in (p / ".git", p, dotgit / ".git", dotgit):
        if cand.is_file() or (cand.is_dir() and is_bare_gitdir(cand, env=False)):
            break
    else:
        return None
    files: list[Path] = []
    gd = cand
    if is_file(cand):
        try:
            if read_file(cand)[:8] != b"gitdir: ":
                return None
        except OSError:
            return None
        gd = read_gitfile(cand)              # git dies on a broken one: refused
        if not (gd.is_dir() and is_bare_gitdir(gd, env=False)):
            return None
        files.append(cand)
    common = gd
    cd = gd / "commondir"
    if cd.is_file():
        files.append(cd)
        common = _resolve_existing(gd / _read_path_file(cd), cd)
    return gd, common, gd, files


_PCT = re.compile(rb"%([0-9A-Fa-f]{2})")
_IS_URL = re.compile(r"[A-Za-z0-9][A-Za-z0-9+.-]*://")     # url.c is_url


def _url_decode(s: str) -> str:
    """git's url_decode_internal (url.c): `%XX` with two hex digits becomes
    that byte, except `%00`; anything else (`%`, `%zz`, `+`) stays as is."""
    out = _PCT.sub(lambda m: m.group(0) if m.group(1) == b"00" else bytes([int(m.group(1), 16)]),
                   os.fsencode(s))
    return os.fsdecode(out)


def submodule_trees(repo: Repo) -> list[tuple[Path, Path]]:
    """(gitdir root, submodule tree) for every nested gitdir that has a
    `core.worktree` (submodules; a linked worktree's gitdir has none and is
    checked when git runs there). A few small files: no measurable cost."""
    out = []
    for r in dict.fromkeys([*gitdir_roots(repo.gitdir), *gitdir_roots(repo.common)]):
        if r in (repo.gitdir, repo.common) or not (r / "config").is_file():
            continue
        wt = config_last(r / "config", "core", "worktree")
        if wt:
            # As is, like git (no `~`, [84]); not strict: after `submodule
            # deinit` the directory may be gone, which refuses nothing here.
            out.append((r, (r / wt).resolve()))
    return out


def _submodule_configs(repo: Repo) -> list[tuple[Path, Path]]:
    """(config file, submodule tree): its relative values resolve there. [39]"""
    return [(r / f, base) for r, base in submodule_trees(repo) for f in ("config", "config.worktree")]


# Keys whose designated directory git reads the content of (hooks executed,
# hooks copied into every new repository). For any other value, only files
# count.
DIR_KEYS = {("core", "hookspath"), ("init", "templatedir")}
OPTIONAL_PREFIX = ":(optional)"         # git 2.52, interpolate_path's callers [91]

# Keys whose value is a path to a file git (or ssh-keygen, curl) reads as
# data and never runs: a signing key, a template, patterns. Not watched. The
# generic rule below (any token that exists as a file) took a `user.signingkey
# = ~/.ssh/id` for a program: hashed on every command, copied into every
# `<key>.d/ext/`, each rotation refused every repository, and `restore` wrote
# the old key back. Mirror of DIR_KEYS: a closed list for a false positive,
# not a blocklist — `gpg.program`, `core.sshCommand`, `credential.helper` name
# programs and stay under the generic rule. `http.<url>.*` matched on the
# section head. [56]
DATA_KEYS = {("user", "signingkey"), ("gpg.ssh", "allowedsignersfile"), ("gpg.ssh", "revocationfile"),
             ("core", "excludesfile"), ("core", "attributesfile"), ("commit", "template"),
             ("blame", "ignorerevsfile"), ("mailmap", "file"), ("diff", "orderfile"),
             ("format", "signaturefile"), ("sendemail", "aliasesfile"),
             ("http", "sslcert"), ("http", "sslkey"), ("http", "sslcainfo"), ("http", "sslcapath"),
             ("http", "cookiefile"), ("http", "pinnedpubkey"),
             # git's own pathname keys (tests/inventory/, [pathname]): the
             # fsck skip lists are object ids, read, never run. [100]
             ("fsck", "skiplist"), ("fetch.fsck", "skiplist"), ("receive.fsck", "skiplist")}


def _data_key(section: str, key: str) -> bool:
    head = section.split(".", 1)[0]
    return (section, key) in DATA_KEYS or (head == "http" and (head, key) in DATA_KEYS)


_SH_SPLIT = re.compile(r"[\s;&|()<>{}=`'\"]+")
_SH_TOPLEVEL = re.compile(r"\$\(\s*git\s+rev-parse\s+--show-toplevel\s*\)"
                          r"|`\s*git\s+rev-parse\s+--show-toplevel\s*`")
_SH_PWD = re.compile(r"\$(?:PWD\b|\{PWD\})")


# `${NAME<op>WORD}`: default, assign, alternate, error (`:-` `-` `:=` `=` `:+`
# `+` `:?` `?`) and the pattern removals (`#` `##` `%` `%%`). WORD holds no
# brace: nested forms are reduced from the inside, one round at a time.
_SH_PARAM = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(:?[-=+?]|##?|%%?)([^{}]*)\}")
# `$(…)` (not `$((…))`, arithmetic) and `` `…` ``, innermost first.
_SH_SUBST = re.compile(r"\$\((?!\()([^()]*)\)|`([^`]*)`")
# A plain parameter: `$NAME`, `${NAME}`, a positional or special one.
_SH_VAR = re.compile(r"\$(?:([A-Za-z_][A-Za-z0-9_]*)|\{([A-Za-z_][A-Za-z0-9_]*)\}|[0-9@*#?$!-])")


def _sh_readings(value: str) -> set[str]:
    """Two readings of `value` that, between them, contain every path sh can
    build from it without running anything gitguard cannot know [58]:
    - `word`: each `${NAME<op>WORD}` gives its WORD (the default, the
      alternate…) and each command substitution gives `.` — `$(pwd)`,
      `` `pwd` ``, `$(dirname …)` glued before `/x` designate the top of
      the tree where git runs the command, and so does a variable gitguard's
      environment does not hold (`x=$(pwd); $x/t.sh`, an alias's `$1`);
    - `var`: each `${NAME…}` gives $NAME's value in gitguard's environment
      (git's), a substitution gives nothing (`$(cmd)/x` = `/x`).
    A superset, like the condition-blind reading of includeIf: hashing a
    file the shell would not reach costs a hash, missing one let a planted
    script run. Then `$VAR`/`${VAR}` through expandvars."""
    def reduce(v: str, word: bool) -> str:
        for _ in range(8):                 # nesting depth; each round strips one level
            w = _SH_PARAM.sub(lambda m: (m.group(3) if m.group(2)[-1] in "-=+?" else "")
                              if word else "" if m.group(2)[-1] == "+"
                              else os.environ.get(m.group(1), ""), v)
            w = _SH_SUBST.sub("." if word else "", w)
            if w == v:
                break
            v = w
        return v
    def unset_as_top(v: str) -> str:
        name = lambda m: m.group(1) or m.group(2)
        return _SH_VAR.sub(lambda m: os.environ.get(name(m), ".") if name(m) else ".", v)
    base = _SH_PWD.sub(".", _SH_TOPLEVEL.sub(".", value))
    return {unset_as_top(reduce(base, True)), os.path.expandvars(reduce(base, False)),
            os.path.expandvars(base)}


def _value_tokens(value: str) -> set[str]:
    """Path candidates of a config value: whitespace split, sh-style split (a
    quoted path, `!"./my tool.sh"`, is a single word for git, which hands the
    value to the shell), the whole value (programs run without a shell), and
    a split on sh operators and `=` (`./t.sh&&x`, `(./t.sh)`, `f() { ./t.sh; }`,
    `T=./t.sh`, `--rcfile=./t`). Done on the value and on its sh readings
    (_sh_readings): `$PWD`, `${PWD}` and `$(git rev-parse --show-toplevel)`
    are the top of the tree (where a `!` alias runs) [37]; `${X:-./t.sh}`,
    `${X:+…}`, `$(pwd)/t.sh`, `` `pwd`/t.sh `` were left as text that names
    no file [58]; other variables come from the environment git inherits
    from gitguard. Candidates, not an interpretation of sh: a path built
    through `cd dir && ./x` or an unset variable glued in a word is an
    accepted limitation ([71], [74], DESIGN.md "Known limitations"); do not
    grow the readings for such variants."""
    toks: set[str] = set()
    for v in {value, *_sh_readings(value)}:
        toks |= set(v.split()) | set(_SH_SPLIT.split(v))
        try:
            toks |= set(shlex.split(v))
        except ValueError:
            pass                          # unbalanced quotes: sh would refuse too
        toks.add(v.strip())
    return {t.lstrip("!").strip("\"'") for t in toks}


def _glued_values(toks: set[str]) -> set[str]:
    """`toks` and, for a short-option word, what may be its value glued to
    it: ssh reads `-F./ssh_config`, `-vF./c` (a cluster: `-v`, then `-F`
    holding the rest) or `-i~/.ssh/k` — an option word was dropped whole,
    hiding the file. A candidate after each letter of the leading run (the
    option letters), not after every character. `--opt=path` is split on
    `=` already. [96]"""
    out = set(toks)
    for t in toks:
        if t.startswith("-") and not t.startswith("--"):
            i = 1
            while i < len(t) and t[i].isalnum():
                i += 1
                out.add(t[i:])
    return out


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
class Entry:
    """One watched file. Value semantics: equal when all five fields are,
    hashable, serialised through `__dict__` (field order = constructor order)."""
    scope: str        # local | common | wt | ext
    path: str         # relative to the scope base (ext: absolute)
    kind: str         # f | l
    mode: str
    sha: str

    def __init__(self, scope: str, path: str, kind: str, mode: str, sha: str) -> None:
        self.scope, self.path, self.kind, self.mode, self.sha = scope, path, kind, mode, sha

    def _key(self) -> tuple[str, str, str, str, str]:
        return (self.scope, self.path, self.kind, self.mode, self.sha)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Entry) and self._key() == other._key()

    def __hash__(self) -> int:
        return hash(self._key())

    def __repr__(self) -> str:
        return "Entry" + repr(self._key())


def _hash_into(h: "hashlib._Hash", p: Path) -> None:
    # O_NONBLOCK: lstat said regular, a FIFO swapped in since must not block. [99]
    with open(p, "rb", opener=lambda f, fl: os.open(f, fl | os.O_NONBLOCK)) as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)


def _hash_file(p: Path, link_zones: tuple[Path, ...] = ()) -> tuple[str, str, str] | None:
    """(kind, mode, sha) of a watched file or symlink; None otherwise
    (FIFO, socket, directory…). A regular file (or a link's target) inside
    one of `link_zones` with another name is refused (_hard_link)."""
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
            _hard_link(p.resolve(), tst, link_zones)
            h.update(b"\0target:")
            _hash_into(h, p)
        return "l", "l", h.hexdigest()
    if not stat.S_ISREG(st.st_mode):
        return None
    _hard_link(p, st, link_zones)
    h = hashlib.sha256()
    _hash_into(h, p)
    return "f", f"{stat.S_IMODE(st.st_mode):o}", h.hexdigest()


def _hard_link(p: Path, st: os.stat_result, link_zones: tuple[Path, ...]) -> None:
    """A watched file must be its only name. Its bytes are checked under
    this path, but git writes many files of the gitdir in place, by name —
    COMMIT_EDITMSG, MERGE_MSG, FETCH_HEAD, the sequencer's files, a reflog
    it appends to — and those are volatile: `.git/COMMIT_EDITMSG` linked to
    `hooks/commit-msg` passed the check with the trusted bytes, then `git
    commit --amend` wrote the sandbox's message into the hook and ran it.
    A symlink there is refused; a hard link is a regular file to lstat.
    Only inside the tree, the gitdir and the common dir (`link_zones`): the
    sandbox can only link() what its mount holds, so both names of a link it
    made lie there. A program the global config names elsewhere may have
    other names — Homebrew ships hard-linked binaries, on the same volume
    as $HOME on macOS — and is left alone: nothing the sandbox writes shares
    its inode. A symlink is judged by its target's path (`p` resolved). [88]"""
    if st.st_nlink > 1 and any(p == z or z in p.parents for z in link_zones):
        raise Refuse(f"hard link in a watched zone: {p} has {st.st_nlink} names, and git "
                     f"writes files of the gitdir by name (COMMIT_EDITMSG, a reflog…), which "
                     f"would rewrite it. Replace it by a copy (copy it aside, move the copy "
                     f"over it), inspect it, then `gitguard trust`.")


def _mk(scope: str, rel: str, p: Path, link_zones: tuple[Path, ...] = ()) -> Entry | None:
    r = _hash_file(p, link_zones)
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


def _volatile_dir(rel: str) -> bool:
    """`rel`: the directory relative to its closest gitdir root (_child_root),
    so that a name only counts at its position — a submodule named `refs` or
    `pack` must not vanish from the fingerprint. [15]"""
    return rel in VOLATILE_DIRS or bool(OBJECT_FANOUT.match(rel))


def _volatile_file(rel: str, is_symlink: bool) -> bool:
    """`rel` is relative to the closest gitdir root (not to the base): a
    submodule's `info/refs` is `modules/<x>/info/refs` seen from the base, and
    `git gc` in that submodule used to alert. [26]"""
    if is_symlink:
        return False                     # a symlink is always an entry, even *.lock
    return (rel.endswith(".lock") or rel in VOLATILE_FILES
            or (rel.startswith("BISECT_") and "/" not in rel))


def gitdir_paths(base: Path) -> Iterator[tuple[str, Path]]:
    """(relative path, path) of everything the gitdir contains outside the
    volatile zones: files and symlinks (a symlink to a directory is an entry,
    never followed). The only walk of the gitdir — fingerprint and name scan
    both use it. The rules are VOLATILE_DIRS/VOLATILE_FILES through
    _volatile_dir/_volatile_file, shared with gitdir_excluded: two copies of
    the same rule had drifted apart ([22])."""
    roots: dict[Path, Path] = {base: base}     # directory → closest gitdir root
    for dirpath, dirnames, filenames in os.walk(base, onerror=_walk_error):
        d = Path(dirpath)
        root = roots[base] if d == base else _child_root(d, roots[d.parent])
        roots[d] = root
        prefix = "" if d == base else str(d.relative_to(base)) + "/"
        rprefix = "" if d == root else str(d.relative_to(root)) + "/"
        keep = []
        for name in dirnames:
            if (d / name).is_symlink():
                filenames.append(name)        # a symlink is an entry
            elif not _volatile_dir(rprefix + name):
                keep.append(name)
        dirnames[:] = keep
        for name in filenames:
            if not _volatile_file(rprefix + name, (d / name).is_symlink()):
                yield prefix + name, d / name


def walk_gitdir(base: Path, scope: str, link_zones: tuple[Path, ...] | None = None) -> Iterator[Entry]:
    """Fingerprint of the gitdir: everything but the volatile (deny-by-default).
    `link_zones`: where a hard link is refused (_hard_link), by default the
    gitdir itself."""
    if link_zones is None:
        link_zones = (base,)
    for rel, path in gitdir_paths(base):
        e = _mk(scope, rel, path, link_zones)
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
        nxt = cur / name
        rel = str(nxt.relative_to(root))
        if (not last or nxt.is_dir()) and _volatile_dir(rel):
            return True
        if last and _volatile_file(rel, nxt.is_symlink()):
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


def walk_tree(scope: str, base: Path, start: Path, repo: Repo | None = None,
              link_zones: tuple[Path, ...] = ()) -> Iterator[Entry]:
    for p in walk_all(start, repo):
        rel = str(p.relative_to(base)) if scope == "wt" else str(p)
        e = _mk(scope, rel, p, link_zones)
        if e:
            yield e


def manifest(repo: Repo, refs: list[tuple[str, Path]]) -> dict[tuple[str, str], Entry]:
    zones = tuple({repo.gitdir, repo.common, repo.root})
    entries: list[Entry] = list(walk_gitdir(repo.gitdir, "local", zones))
    if repo.common != repo.gitdir:
        entries += walk_gitdir(repo.common, "common", zones)
    for scope, p in refs:
        entries += walk_tree(scope, repo.root, p, repo, zones)
    # The system and global config files are parsed (config_refs) for the
    # paths they name, never hashed: the sandbox cannot write them, and
    # whoever can (HOME mounted) can write the state directory too. Hashing
    # them turned every registered repository "modified" at each
    # `git config --global` / `git lfs install`. [56]
    return {(e.scope, e.path): e for e in entries}


class Inspection:
    """Everything a check needs about one repository, computed once by
    `inspect` in the one order that is safe: the config scan (what git will
    read), the structural refusals (which need the roots the scan found),
    then the fingerprint. The state blessed by `save_trust` is always the
    `new` of an Inspection that was shown, never recomputed."""

    def __init__(self, repo: Repo, scan: ConfigScan, new: dict[tuple[str, str], Entry]) -> None:
        self.repo, self.scan, self.new = repo, scan, new

    @property
    def refs(self) -> list[tuple[str, Path]]:
        return self.scan.refs


def inspect(repo: Repo) -> Inspection:
    """config_refs → check_structure → manifest. Raises Refuse on a
    structural problem; the fingerprint is not computed then."""
    scan = config_refs(repo)
    check_structure(repo, scan.refs)
    return Inspection(repo, scan, manifest(repo, scan.refs))


# -------------------------------------------------------------------- state
def scope_base(repo: Repo, scope: str) -> Path:
    return {"local": repo.gitdir, "common": repo.common, "wt": repo.root}.get(scope, Path("/"))


class Manifest:
    """Recorded trust state. `current` false = written by an earlier version:
    to be re-validated (`retrust`), never compared."""
    version: int
    root: str | None
    refs: list[tuple[str, Path]]            # roots designated by the trusted config
    entries: dict[tuple[str, str], Entry]

    def __init__(self, version: int, root: str | None, refs: list[tuple[str, Path]],
                 entries: dict[tuple[str, str], Entry]) -> None:
        self.version, self.root, self.refs, self.entries = version, root, refs, entries

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


def save_trust(repo: Repo, refs: list[tuple[str, Path]],
               man: dict[tuple[str, str], Entry]) -> None:
    """Record `man` as the reference. The caller passes the state it computed
    and showed (an Inspection's `refs` and `new`): we validate exactly what
    was seen, never a recomputed state the container could have altered in
    the meantime. No default: the function cannot compute one."""
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
    import shutil
    bak = Path(str(key) + ".d")
    new = Path(str(key) + ".d.tmp")
    shutil.rmtree(new, ignore_errors=True)
    new.mkdir()
    (new / ".root").write_text(str(repo.label) + "\n")
    for (scope, rel), e in man.items():
        if scope == "ext":
            continue                     # hashed, never copied: see restore
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
    import shutil
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
    remove it. The flock is taken on the state directory itself, one lock
    for every record: the critical section is a JSON read and write, and a
    `<key>.pending.lock` file could never be removed (unlinking a lock file
    under a holder lets a third process take a second "exclusive" lock on a
    fresh inode), so every `trust` left one behind for ever. [57]"""
    import fcntl
    STATE.mkdir(parents=True, exist_ok=True)
    STATE.chmod(0o700)
    fd = os.open(str(STATE), os.O_RDONLY)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        new = fn(load_pending(key))
        p = pending_path(key)
        if new is None:
            p.unlink(missing_ok=True)
        else:
            tmp = Path(str(p) + ".tmp")
            tmp.write_text(json.dumps(new, indent=1, ensure_ascii=False))
            os.replace(tmp, p)
        return new
    finally:
        os.close(fd)                     # releases the lock


def clear_pending(key: Path) -> None:
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
    import subprocess
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
    import subprocess
    try:
        subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=3)
    except Exception:                    # noqa: BLE001 — best effort by design
        pass


def record_pending(key: Path, kind: str, label, message: str,
                   new: dict | None = None, refs: list[tuple[str, Path]] | None = None,
                   waiter: dict | None = None, notify_user: bool = True) -> None:
    """Create or refresh `<key>.pending` (kind: changed | never | structural)
    and notify once per NOTIFY_COOLDOWN. `new`/`refs` (changed only) describe
    the latest state seen; `waiter` registers the blocked process. A child
    git (`notify_user` False) records without notifying: its parent's
    stderr carries the message."""
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
    if notify and notify_user:
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
            _print_diff(old_cfg, cfg)


def _config_lines(p: Path) -> list[str]:
    """The lines of a config file as git splits them: on LF only, a CR right
    before it dropped (CRLF). Not read_text().splitlines(): a lone CR (or VT,
    FF, U+2028…) became a line break, and `hooksPath = .githooks<CR>x = y`,
    one value for git, showed as two clean lines before [y/N]. The CR stays
    in its line, where san() shows it as `?`. [53]"""
    text = p.read_bytes().decode(errors="replace")
    lines = text.split("\n")
    if text.endswith("\n"):
        lines.pop()                  # the terminator, not an empty last line
    return [l[:-1] if l.endswith("\r") else l for l in lines]


def _print_diff(old_cfg: Path, cfg: Path) -> None:
    import difflib
    a = _config_lines(old_cfg)
    b = _config_lines(cfg)
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
    plan = [(("delete" if a == "added" else "restore"), k) for a, k in changes(old, new)]
    # A deletion may only target the inside of the gitdir or of a root that the
    # **trusted** config designated. Without this, an `ext:` path that appeared
    # after the trust (hooksPath turned into a symlink to $HOME, say) made
    # gitguard delete files outside the repository — found in review. Such a
    # file is left in place and named, and the rest is restored: it is only
    # watched because the planted config names it (`include.path = ../x`),
    # and once that config is back it is an ordinary file, in the tree or
    # outside, for the user to look at. Refusing the whole restore left the
    # hook and the config in place too (seen with a container planting the
    # three at once).
    allowed = [repo.gitdir, repo.common] + [p for _, p in trusted_refs]
    kept = []
    # Outside the repository (scope `ext`: `../shared-hooks`, a program under
    # $HOME named by the config) gitguard writes nothing and deletes nothing,
    # and keeps no copy in the state directory. Two of its own flaws were
    # restore acting there — neighbouring files deleted [25], a rotated ssh
    # key overwritten with the old one [56] — for files it only watches
    # because the config names them. They are named here, for the user.
    for action, (scope, path) in list(plan):
        if scope == "ext":
            plan.remove((action, (scope, path)))
            kept.append((scope, path))
            warn(f"{_label(scope, path)} is outside the repository: left in place, neither "
                 f"restored nor deleted by gitguard. Inspect it by hand.")
    for action, (scope, path) in list(plan):
        if action != "delete":
            continue
        target = (scope_base(repo, scope) / path).resolve()
        if not any(a == target or a in target.parents for a in allowed):
            plan.remove((action, (scope, path)))
            kept.append((scope, path))
    for scope, path in kept:
        warn(f"{_label(scope, path)} is outside the paths designated by the trusted config: "
             f"left in place, not deleted. Inspect it by hand.")
    for action, (scope, path) in list(plan):     # a backup written by an older version
        copy = bak / scope / path.lstrip("/")
        if action == "restore" and not (copy.is_symlink() or copy.is_file()):
            plan.remove((action, (scope, path)))
            kept.append((scope, path))
            warn(f"{_label(scope, path)}: no backup copy: left as is. Inspect it by hand, "
                 f"then `gitguard trust`.")
    if not plan:
        if kept:
            raise Refuse("nothing else to restore")
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
    if manifest(repo, config_refs(repo).refs) == old:
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
            insp = inspect(open_repo(root))
        except Refuse:
            yield key, root, "structure"
            continue
        if data is None or not data.current:
            yield key, root, "legacy"
        elif insp.new != data.entries:
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
    check_wrap()


def forget_key(key: Path) -> None:
    for suffix in ("", ".tmp", ".idx", ".idx.tmp", ".pending", ".pending.tmp", ".pending.lock"):
        p = Path(str(key) + suffix)
        if p.exists():
            p.unlink()
    import shutil
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
        # A never-trusted repository has a record but no manifest, so
        # entries() does not list it: once deleted, its record stayed. [57]
        for p in sorted(STATE.glob("????????????????.pending")):
            key = Path(str(p)[:-len(".pending")])
            if key.is_file():
                continue
            d = load_pending(key)
            root = d.get("root") if d else None
            if root is None or not Path(root).is_dir():
                forget_key(key)
                n += 1
                info(f"forgotten: {root or key.name}")
        # Lock files of earlier versions, nothing takes them any more. [57]
        for p in STATE.glob("????????????????.pending.lock"):
            p.unlink(missing_ok=True)
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
            insp = inspect(open_repo(root))
            save_trust(insp.repo, insp.refs, insp.new)
            clear_pending(key)
            n += 1
            info(f"re-trusted: {root}")
        else:
            skipped += 1
            warn(f"skipped ({st}): {root or key.name}")
    info(f"{n} repository(ies) re-trusted, {skipped} skipped")
    check_safe_bare()
    check_wrap()


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
    insp = inspect(open_repo(label))
    repo, refs, live = insp.repo, insp.refs, insp.new
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
                   "--attr-source", "--shallow-file"}
GLOBAL_WITH_EQ = ("--config-env=", "--namespace=", "--git-dir=", "--work-tree=",
                  "--attr-source=", "--shallow-file=", "--exec-path=",
                  "--list-cmds=")
GLOBAL_FLAGS = {"-p", "--paginate", "-P", "--no-pager", "--no-replace-objects",
                "--literal-pathspecs", "--no-literal-pathspecs", "--glob-pathspecs",
                "--noglob-pathspecs", "--icase-pathspecs", "--no-optional-locks",
                "--no-advice", "--no-lazy-fetch", "--exec-path", "--html-path",
                "--man-path", "--info-path"}
GLOBAL_STOP = {"-h", "--help", "-v", "--version"}   # git turns them into a command


class GlobalOpts:
    cwd: Path                 # effective cwd after the -C options (not canonicalised)
    gitdir: Path | None       # --git-dir, relative to that cwd
    worktree: Path | None     # --work-tree, relative to that cwd
    rest: list[str]           # from the subcommand onwards
    config: list[str]         # -c arguments (`key=value`)
    config_env: list[str]     # --config-env arguments (`key=VAR`)

    def __init__(self, cwd: Path, gitdir: Path | None, worktree: Path | None,
                 rest: list[str], config: list[str] | None = None,
                 config_env: list[str] | None = None) -> None:
        self.cwd, self.gitdir, self.worktree, self.rest = cwd, gitdir, worktree, rest
        self.config = [] if config is None else config
        self.config_env = [] if config_env is None else config_env

    def __repr__(self) -> str:
        return (f"GlobalOpts({self.cwd!r}, {self.gitdir!r}, {self.worktree!r}, "
                f"{self.rest!r}, {self.config!r}, {self.config_env!r})")


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
        if a == "--bare":
            # `setenv(GIT_DIR, getcwd(), 0)` (handle_options): the cwd as it
            # is at this point (after the `-C` before it), unless a GIT_DIR is
            # already there; a `--git-dir` overwrites it, before or after.
            # Taken for an inert flag, gitguard discovered the repository
            # from the cwd and checked its `.git`, while git read the
            # `config` a sandbox laid out at the root of the tree. [97]
            i += 1
            if gitdir is None and not os.environ.get("GIT_DIR"):
                gitdir = str(cwd.resolve())
            continue
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


# The options of `git clone` and `git init` (git 2.50 and 2.54, `git clone
# -h`, `git init -h`; test_new_repo_options_match_git holds these tables to
# the git under test): each long option, True when it takes a separate
# value (`--branch x`; `--shared[=<perm>]` only an attached one), then the
# short options that take one. parse-options accepts any unique prefix of a
# long option, `--no-` forms included: `--templ=<dir>` is `--template`. [98]
NEW_REPO_OPTIONS: dict[str, tuple[dict[str, bool], str]] = {
    "clone": ({**dict.fromkeys(
        ["--verbose", "--quiet", "--progress", "--reject-shallow", "--no-checkout",
         "--checkout", "--bare", "--mirror", "--local", "--no-hardlinks", "--hardlinks",
         "--shared", "--recurse-submodules", "--recursive", "--dissociate",
         "--single-branch", "--tags", "--shallow-submodules", "--ipv4", "--ipv6",
         "--also-filter-submodules", "--remote-submodules", "--sparse"], False),
        **dict.fromkeys(
        ["--jobs", "--template", "--reference", "--reference-if-able", "--origin",
         "--branch", "--revision", "--upload-pack", "--depth", "--shallow-since",
         "--shallow-exclude", "--separate-git-dir", "--ref-format", "--config",
         "--server-option", "--filter", "--bundle-uri"], True)}, "jobuc"),
    "init": ({**dict.fromkeys(["--bare", "--shared", "--quiet"], False),
              **dict.fromkeys(["--template", "--separate-git-dir", "--initial-branch",
                               "--object-format", "--ref-format"], True)}, "b"),
}


def _long_option(name: str, longs: dict[str, bool]) -> tuple[str | None, bool]:
    """(the long option `name` stands for, negated?) as parse-options reads
    it: itself, else the one option it is a unique prefix of; `--no-x` is
    x negated unless `--no-x` is an option of its own (`--no-checkout`).
    None: unknown or ambiguous (git dies)."""
    for cand, neg in ((name, False), ("--" + name[5:], True) if name.startswith("--no-") else (None, False)):
        if cand is None:
            continue
        if cand in longs:
            return cand, neg
        hits = [o for o in longs if o.startswith(cand)]
        if len(hits) == 1:
            return hits[0], neg
    return None, False


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
    return any(s == "init" and k == "templatedir" for _, s, k, _ in iter_global_config())


class NewRepo:
    """What `clone` or `init` creates: `dir`, the repository's directory (the
    gitdir itself when bare); `gitdir` when `--separate-git-dir` puts it
    elsewhere; `auto_trust`: not for a bare repository (gitguard does not
    handle those) nor for one built from a template, whose hooks nobody
    reviewed ([42] [98]). Every form sets the `new` marker: the children
    (`index-pack`, the submodule clones) run before the repository exists,
    in it ([101])."""

    def __init__(self, sub: str, dir: Path, gitdir: Path | None = None,
                 auto_trust: bool = True) -> None:
        self.sub, self.dir, self.gitdir, self.auto_trust = sub, dir, gitdir, auto_trust

    @property
    def paths(self) -> list[str]:
        return [str(self.dir.resolve())] + ([str(self.gitdir.resolve())] if self.gitdir else [])


def _guess_dir_name(repo: str, bundle: bool, bare: bool) -> str | None:
    """git_url_basename (dir.c): the directory `git clone <repo>` creates.
    The scheme and a `user@` before the first separator skipped; trailing
    separators and blanks dropped, then a trailing `/.git` and the
    separators before it (`x/.git` → `x`: the former reading gave an empty
    name, a `new` marker covering the whole cwd, and no auto-trust [110]);
    the `:<port>` of a bare `host:port`; the last component after a `/` or a
    `:` (`host:repo.git` → `repo`); a `.bundle` or `.git` suffix; `.git`
    appended for a bare clone; runs of control characters and blanks become
    one space, none at the ends. None: git dies ("No directory name could
    be guessed")."""
    v = repo.partition("://")[2] if "://" in repo else repo
    head = v.split("/", 1)[0]
    if "@" in head:
        v = v[head.rindex("@") + 1:]
    v = v.rstrip("/ \t\n\r")                              # is_dir_sep, git's isspace
    if len(v) > 5 and v[-5] == "/" and v.endswith(".git"):
        v = v[:-5].rstrip("/")
    if "/" not in v and ":" in v:
        i = len(v)
        while i > 0 and v[i - 1] in "0123456789":
            i -= 1
        if i > 0 and v[i - 1] == ":":
            v = v[:i - 1]
    i = len(v)
    while i > 0 and v[i - 1] not in "/:":
        i -= 1
    name = v[i:]
    suffix = ".bundle" if bundle else ".git"
    if name.endswith(suffix):
        name = name[:-len(suffix)]
    if not name or name == "/":
        return None
    if bare:
        name += ".git"
    out, prev_space = [], True
    for ch in name:
        if ord(ch) < 0x20:
            ch = " "
        if ch == " ":
            if prev_space:
                continue
            prev_space = True
        else:
            prev_space = False
        out.append(ch)
    return "".join(out).rstrip(" ")


def parse_new_repo(args: list[str]) -> NewRepo | None:
    """The repository the command creates (clone, init), else None."""
    o = split_global_options(args, Path.cwd())
    cwd = o.cwd.resolve()
    if not o.rest or o.rest[0] not in ("clone", "init"):
        return None
    sub, rest, positional, bare, template = o.rest[0], o.rest[1:], [], False, False
    gitdir: Path | None = None
    longs, shorts = NEW_REPO_OPTIONS[sub]
    j = 0
    while j < len(rest):
        a = rest[j]
        if a == "--":
            positional += rest[j + 1:]; break
        if a.startswith("--"):
            name, eq, _ = a.partition("=")
            opt, neg = _long_option(name, longs)
            # Anything that may stand for --template counts as it, ambiguous
            # prefixes included (git dies on those): fail closed. [98]
            if opt == "--template" or (opt is None and len(name) > 2
                                       and "--template".startswith(name)):
                template = not neg
            elif opt in ("--bare", "--mirror"):
                bare = not neg
            elif opt == "--separate-git-dir" and not neg:
                val = a.partition("=")[2] if eq else (rest[j + 1] if j + 1 < len(rest) else "")
                gitdir = cwd / val if val else None
            j += 2 if opt is not None and longs[opt] and not neg and not eq else 1
        elif a.startswith("-") and len(a) > 1:
            # A cluster (`-qb main`): the first letter that takes a value
            # ends it, holding the rest of the word or the next argument.
            k = next((i for i, c in enumerate(a[1:], 1) if c in shorts), None)
            j += 2 if k == len(a) - 1 else 1
        else:
            positional.append(a); j += 1
    auto_trust = not bare
    if template or _template_dir_configured(o.config + o.config_env):
        warn("templateDir: no auto-trust, run 'gitguard trust' after inspection")
        auto_trust = False
    if sub == "clone":
        if not positional:
            return None
        if len(positional) >= 2:
            d = positional[1]
        else:
            src = positional[0]
            d = _guess_dir_name(src, bundle=(cwd / src).is_file(), bare=bare)
            if d is None:
                return None
    else:
        d = positional[0] if positional else "."
    return NewRepo(sub, cwd / d, gitdir, auto_trust)


# `git push` options taking a separate value (git 2.47 and 2.50, `git push
# -h`): their value is not the repository. Long options may be abbreviated
# (parse-options): a unique prefix of any long option counts as it.
PUSH_WITH_ARG = {"--repo", "--receive-pack", "--exec", "--push-option", "--recurse-submodules"}
PUSH_LONG = PUSH_WITH_ARG | {
    "--verbose", "--quiet", "--all", "--branches", "--mirror", "--delete", "--tags",
    "--dry-run", "--porcelain", "--force", "--force-with-lease", "--force-if-includes",
    "--thin", "--set-upstream", "--progress", "--prune", "--no-verify", "--verify",
    "--follow-tags", "--signed", "--atomic", "--ipv4", "--ipv6"}


def _push_destination(args: list[str]) -> str | None:
    """The <repository> of `git push [<options>] [<repository> [<refspec>…]]`,
    or `--repo`'s value when no positional one is given; None: the default
    remote, from the config."""
    repo_opt, i = None, 0
    while i < len(args):
        a = args[i]
        if a == "--":
            return args[i + 1] if i + 1 < len(args) else repo_opt
        if a.startswith("--"):
            name, eq, val = a.partition("=")
            bare = name[len("--no-"):] if name.startswith("--no-") else None
            full = [o for o in PUSH_LONG if o == name] or [o for o in PUSH_LONG if o.startswith(name)]
            opt = full[0] if len(full) == 1 else None
            if bare is None and opt in PUSH_WITH_ARG and not eq:
                if opt == "--repo" and i + 1 < len(args):
                    repo_opt = args[i + 1]
                i += 2
                continue
            if opt == "--repo" and eq:
                repo_opt = val
        elif a.startswith("-") and len(a) > 1:
            j = a.find("o", 1)                   # `-o` takes a value: attached or next
            if j != -1 and j == len(a) - 1:
                i += 2
                continue
        else:
            return a
        i += 1
    return repo_opt


def _archive_remote(args: list[str]) -> str | None:
    """`git archive`'s `--remote`: cmd_archive parses it with
    PARSE_OPT_KEEP_ALL (git 2.47 and 2.50, checked by hand): anywhere before
    `--`, `--remote=<r>` or `--remote <r>`, never abbreviated, the last one
    wins, `--no-remote` clears it; `-o`, `--output`, `--exec` take the next
    argument as their value. Only `-o` itself: `-ofile` holds its value, and
    a cluster starting with any other letter (`-vo`, `-9o`) is an unknown
    option kept whole for the remote, the next argument still parsed."""
    remote, i = None, 0
    while i < len(args):
        a = args[i]
        if a == "--":
            break
        if a in ("--remote", "--output", "--exec", "-o"):
            if a == "--remote" and i + 1 < len(args):
                remote = args[i + 1]
            i += 2
            continue
        if a.startswith("--remote="):
            remote = a[len("--remote="):]
        elif a == "--no-remote":
            remote = None
        i += 1
    return remote


def _legacy_remote_urls(repo: Repo, name: str) -> list[str]:
    """URLs of a remote defined the old way, `.git/remotes/<name>` (`URL:`
    lines) or `.git/branches/<name>` (`<url>#<branch>`): git still reads them."""
    out = []
    p = repo.common / "remotes" / name
    if "/" not in name and p.is_file():
        out += [ln[4:].strip() for ln in p.read_text(errors="replace").split("\n")
                if ln.startswith("URL:")]
    p = repo.common / "branches" / name
    if "/" not in name and p.is_file():
        out += [p.read_text(errors="replace").split("\n", 1)[0].split("#", 1)[0].strip()]
    return out


def check_remote_destination(repo: Repo, rest: list[str], remote_names: set[str],
                             refs: list[tuple[str, Path]]) -> None:
    """`git push <path>` to a local repository that no trusted config names:
    receive-pack runs that repository's hooks and honours its config, and
    nothing of it is in the fingerprint (only configured remotes are, [45]
    [61]). Refused, the way out named: make it a remote, then trust. A
    relative path is relative to the root of the tree (git chdirs there).
    Not seen: a push through an alias, `url.<base>.insteadOf` rewriting a
    URL into a local path, `send-pack`. Allowed: the repository itself
    (`git push . main:x`) and a repository a configured remote already
    designates (its config is in `refs`, watched). [62]
    `git archive --remote=<path>` likewise: upload-archive runs in that
    repository and executes its `tar.<format>.command`. [70]"""
    if not rest or rest[0] not in ("push", "archive"):
        return
    cmd = rest[0]
    dest = (_push_destination if cmd == "push" else _archive_remote)(rest[1:])
    if dest is None or dest in remote_names:
        return
    urls = _legacy_remote_urls(repo, dest) or [dest]
    for url in urls:
        r = _local_remote(url, repo.root)
        watched = {p for _, p in refs}
        if r is not None and r[1] != repo.common and (r[1] / "config") not in watched:
            again = "push <name>" if cmd == "push" else "archive --remote=<name>"
            raise Refuse(f"`git {cmd}` to {dest}: a local repository no trusted config names "
                         f"({r[0]}); git would run its hooks and config, which gitguard does "
                         f"not watch. Make it a remote (`git remote add <name> {url}`), run "
                         f"`gitguard trust`, then `git {again}`. [{62 if cmd == 'push' else 70}]")


def check_archive_outside_repo(rest: list[str]) -> None:
    """`git archive --remote=<path>` from a directory that is no repository:
    no config to name remotes, nothing fingerprinted, and git still starts
    upload-archive in that repository, which runs its `tar.<format>.command`.
    Refused when the destination is a local repository (relative to the cwd:
    git does not move); the way out runs the archive there, checked like any
    command. [81]"""
    if not rest or rest[0] != "archive":
        return
    dest = _archive_remote(rest[1:])
    if dest is None:
        return
    r = _local_remote(dest, Path.cwd())
    if r is not None:
        raise Refuse(f"`git archive --remote={dest}` outside any repository: {r[0]} is a "
                     f"local repository, git would run its config (tar.<format>.command), "
                     f"which gitguard does not watch. Run it there instead: "
                     f"`git -C {dest} archive …`. [81]")


def _split_cmdline(value: str) -> list[str] | None:
    r"""Port of git's split_cmdline (alias.c): words separated by runs of
    git's isspace (no \v, no \f), `'` and `"` quotes, `\` escaping outside
    single quotes. A leading blank yields an empty first word, a trailing one
    an empty last word, as in git. None where git dies ("bad alias.<name>
    string": unclosed quote, `\` at the end). [66]"""
    words: list[str] = []
    cur: list[str] = []
    quoted, i = "", 0
    while i < len(value):
        c = value[i]
        if not quoted and c in " \t\n\r":
            words.append("".join(cur))
            cur = []
            i += 1
            while i < len(value) and value[i] in " \t\n\r":
                i += 1
            continue
        if not quoted and c in "'\"":
            quoted = c
        elif c == quoted:
            quoted = ""
        else:
            if c == "\\" and quoted != "'":
                i += 1
                if i >= len(value):
                    return None
                c = value[i]
            cur.append(c)
        i += 1
    if quoted:
        return None
    words.append("".join(cur))
    return words


def _alias_parts(value: str) -> tuple[str | None, list[tuple[str, str | None]]]:
    """A git (non-`!`) alias as git's handle_alias runs it: the words of
    split_cmdline, then the global options at their head (handle_options),
    then the command. Returns the command (None: none, or git dies) and the
    config the alias sets for that run: its `-c k=v` (v None for a bare `k`,
    git's true) and its `--config-env k=VAR` resolved from the environment.
    git accepts only `-p`, `-c` and `--config-env` in an alias and dies on
    the others ("changes environment variables", unknown option); they are
    skipped here, with their argument — a superset: a command found where git
    dies runs nothing. [79] [80]"""
    if value.startswith("!"):
        return None, []
    words = _split_cmdline(value)
    if words is None:
        return None, []
    pairs: list[tuple[str, str | None]] = []
    i = 0
    while i < len(words) and words[i].startswith("-"):
        w = words[i]
        if w in GLOBAL_STOP:
            return None, pairs                 # git turns it into `help`/`version`
        if w in ("-c", "--config-env") or w.startswith("--config-env="):
            if w.startswith("--config-env="):
                spec, i = w[len("--config-env="):], i + 1
            elif i + 1 < len(words):
                spec, i = words[i + 1], i + 2
            else:
                return None, pairs             # git dies: option without its argument
            if w == "-c":
                k, eq, v = spec.partition("=")
                pairs.append((k, v if eq else None))
            else:
                k, eq, var = spec.rpartition("=")
                if eq and var in os.environ:
                    pairs.append((k, os.environ[var]))
        elif w in GLOBAL_WITH_ARG:
            i += 2
        else:
            i += 1
    return (words[i] or None) if i < len(words) else None, pairs


def run_git(args: list[str], orig: Path, newrepo: NewRepo | None, git: str,
            judged: Judged | None = None) -> int:
    """Run the real git. A clone/init is waited for and the new repository
    trusted (Auto-trust), by a child git too (pre-commit's cache, a hook's
    clone [107]) — unless the marker already covers it: `submodule add`'s
    clone into `modules/<x>`, the submodules of `clone --recurse-submodules`
    are part of the judged repository, which the parent's next command, or
    the clone's own auto-trust, takes as a whole."""
    os.chdir(orig)
    if newrepo is None:
        os.execv(git, [git, *args])
    import subprocess
    d = newrepo.dir
    preexisting = (d / ".git").exists() or (d / ".git").is_symlink()
    set_judged("new", *newrepo.paths)     # its children, the submodule clones included
    rc = subprocess.call([git, *args])
    if rc == 0 and newrepo.auto_trust:
        d = d.resolve()
        if preexisting:
            warn(f"{d} already contained a .git before '{newrepo.sub}': no auto-trust (gitguard trust after inspection)")
        elif (d / ".git").exists():
            # The new repository, whatever the environment designates: a
            # child's GIT_DIR is its parent's (git exports it to `submodule
            # add`'s clone), and open_repo would have judged the superproject.
            for k in ("GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_INDEX_FILE"):
                os.environ.pop(k, None)
            try:
                insp = inspect(open_repo(d))
                if judged is None or not judged.covers(insp.repo):
                    save_trust(insp.repo, insp.refs, insp.new)
                    info(f"new repository trusted: {d}")
            except Refuse as e:
                warn(f"cannot trust {d} automatically: {e}")
    return rc


# ------------------------------------------------- auto-accept and prompt
_BRANCH_KEYS = {"remote", "merge", "vscode-merge-base"}
_REF_OK = re.compile(r"^refs/heads/[^\s]+$")
# `branch.<x>.vscode-merge-base = origin/main`: written by VS Code's git
# extension when a repository is opened (seen with code-server on the VM:
# every repository turned "modified" on first open). git ignores the key;
# VS Code passes the value to `git merge-base` as a ref name. Accepted when it
# looks like one: no leading `-` (an option), no blank, no control character.
_REFNAME_OK = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/@{}^~-]*$")


def branch_tracking_only(old_items: list[tuple[str, str, str]],
                         new_items: list[tuple[str, str, str]]) -> list[str]:
    """If the only semantic difference between two configs is the addition or
    removal of `branch.<x>.remote` / `branch.<x>.merge` (what `push -u`,
    `branch -u` and `checkout -b` with autoSetupMerge write) or of
    `branch.<x>.vscode-merge-base` (what VS Code's git extension writes on
    opening a repository), return the branches concerned; otherwise []. None
    of these keys can make anything run. `remote` must name a remote already
    present in the trusted config (or `.`), `merge` a `refs/heads/…`,
    `vscode-merge-base` a ref name. Closed list, not to be extended without
    proof: this is not a blocklist of dangerous keys but an allowlist of
    three harmless ones — the fingerprint remains the rule for everything
    else."""
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
        if key == "vscode-merge-base" and not _REFNAME_OK.match(value):
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
    import termios
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
    import subprocess
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


# ----------------------------------------------------------- passthroughs
# Invocations handed to the real git before any check. A closed list: every
# entry is an exception to "check, then run" and carries its proof that git
# opens no repository of the cwd there. Never add a subcommand on the ground
# that it "only reads": `git log` reads the config (pager, diff drivers).
#
# - `--version`, `version` as the first argument: git.c maps `--version` to
#   the `version` command, which has no RUN_SETUP flag — no
#   setup_git_directory, hence no repository config, no `pager.version`,
#   no alias. lazygit and fugitive probe it first and took gitguard's
#   refusal for an old git. `git -p version` or `git -C x version` is not
#   on the list: a global option first means the full check.
# - `git-receive-pack`, `git-upload-pack`, `git-upload-archive` as the
#   invoked name: on Debian they are symlinks to `/usr/bin/git`, so with the
#   system-wide install sshd runs gitguard under those names for every push
#   and fetch *to* the machine. They serve a repository named by argument
#   (a bare one, which gitguard does not handle) and run nothing of the
#   cwd's; a local push already reaches them unwrapped through the real
#   git's exec path. Every ssh push to the VM failed before this entry.
# - `--exec-path`, `--html-path`, `--man-path`, `--info-path` as the first
#   argument: handle_options (git.c) prints the path and exit(0)s before
#   any setup. The exec path's shell scripts (`git-submodule`,
#   `git-mergetool`, `git-request-pull`…) start with `.
#   "$(git --exec-path)/git-sh-setup"`: with a check in the way, in a
#   never-trusted repository, the output was empty and `git-submodule` died
#   on "cannot open /git-sh-i18n". `--exec-path=<dir>` (sets it) is not on
#   the list.
TRANSPORT = {"git-receive-pack": "receive-pack", "git-upload-pack": "upload-pack",
             "git-upload-archive": "upload-archive"}
SERVERS = tuple([v] for v in TRANSPORT.values())
VERSION_ARGS = (["--version"], ["version"])
PATH_QUERIES = (["--exec-path"], ["--html-path"], ["--man-path"], ["--info-path"])


def passthrough(name: str, args: list[str]) -> list[str] | None:
    """The real git's arguments when the invocation (`name` = argv[0]'s
    basename, `args` = the git arguments) is on the list above; else None."""
    if name in TRANSPORT:
        args = [TRANSPORT[name], *args]
    if args[:1] in VERSION_ARGS or args[:1] in PATH_QUERIES:
        return args
    if args[:1] in SERVERS:
        # Also as the first word: `git daemon`, `git http-backend` and
        # `git-shell` run `git upload-pack <dir>` ([106]). Its children
        # (`index-pack`, `pack-objects`, `update-server-info`,
        # `maintenance`, the hooks) run in the served repository, a bare one
        # gitguard does not handle: they inherit a marker for it — for it
        # alone: a marker covering anything let a `post-receive` of the hub
        # that runs `cd site && git pull` enter `site` unjudged. [105]
        # Without a marker every ssh push to the host died in `index-pack`
        # once gitguard sat at the exec path — the incident that created
        # TRANSPORT, one level down.
        served = _served_repository(args[1:])
        if served is not None:
            set_judged("repo", str(served[0]), str(served[1]), "")
        return args
    return None


def _served_repository(args: list[str]) -> tuple[Path, Path, Path, list[Path]] | None:
    """The repository `receive-pack`, `upload-pack` or `upload-archive`
    serve: their one positional argument (every option is a flag or
    `--opt=value`; `--timeout <n>` of upload-pack takes a separate number),
    opened as enter_repo opens it (_local_remote). None: no argument or no
    repository there — git dies on it, and a child would judge for itself."""
    pos = [a for i, a in enumerate(args)
           if "--" in args[:i] or (not a.startswith("-") and not (i and args[i - 1] == "--timeout"))]
    return _local_remote(pos[-1], Path.cwd()) if pos else None


# ------------------------------------------------------------- child gits
# Every git enters another repository through a child process, and the
# child is `<exec-path>/git` (setup_path puts the exec path first in its
# PATH): with gitguard diverted there, every child is gitguard
# (DESIGN-exec-path.md). A marker in the environment of the git gitguard
# runs says which repository this command has already judged: a child in
# that repository does not judge it again — what the command itself writes
# (`submodule add`, `remote add`, `push -u`) is judged at the next command,
# as before — while a child in any other repository, a submodule or a
# planted `vendor/x`, judges it as a first process would, and refuses a
# repository never trusted. No route to guess: whatever enters, enters
# through gitguard. The environment is trusted here as everywhere else
# (`GITGUARD_REAL_GIT`, `GIT_DIR`): whoever sets the user's environment is
# outside the model (DESIGN.md, Known limitations).
JUDGED_ENV = "GITGUARD_JUDGED"


class Judged:
    """The marker, parsed: `<pid>:repo=<gitdir>,<common>,<root>` (a
    repository judged: its resolved gitdir, common dir and work tree root —
    the root empty for a served repository, whose tree is not in question)
    or `<pid>:new=<path>[,<gitdir>]` (a clone/init in progress: the
    repository does not exist yet; it and its submodule clones are under
    `path`, its gitdir at `gitdir` for `--separate-git-dir`). Paths are
    hex-encoded: they hold anything but NUL. `pid`: the process that set
    the marker — gitguard, which execs the real git under its own pid, or
    stays its parent for a clone. The marker is valid while that process is
    an ancestor of this one: the lifetime of the command, however long (a
    `clone --recurse-submodules` of a large tree, `filter-branch`), and not
    a moment more — an environment variable outliving its git (a detached
    shell) names a pid that is no ancestor, and a pid reused by another
    process is never in a live ancestor chain. A clock changed the answer
    mid-command, not only its cost: with a 60 s TTL, every submodule of a
    clone longer than a minute was refused. [104]"""

    def __init__(self, pid: int, kind: str, paths: list[str]) -> None:
        self.pid, self.kind, self.paths = pid, kind, paths

    @cached_property
    def alive(self) -> bool:
        return self.pid in _ancestors()

    def covers(self, repo: Repo) -> bool:
        """Is `repo` what this marker judged? What the parent's walk hashed
        (DESIGN.md, "What the fingerprint watches in the gitdir"): the judged
        gitdir and common dir and every gitdir root nested under their
        `modules/` and `worktrees/` (gitdir_roots, the walk's own
        recognition, _child_root). The child's resolved gitdir and common
        dir must both be among them — a gitdir planted in a volatile zone of
        a submodule (`modules/x/refs/p`), hashed by nobody, is judged on its
        own and refused ([103]); the former rule, the name `.git` and a
        prefix, covered it, and covered none of a worktree's or a separate
        gitdir's submodules ([102]). The same gitdir with another work tree
        is another repository for the tree-side references ([72]): judged.
        A clone in progress covers anything whose gitdir, common dir or root
        is under the new path ([101]: the clone's index-pack runs with
        `GIT_DIR=<new>/.git` from the user's cwd; compared by root alone,
        every clone but of a plain local path died "never trusted")."""
        if self.kind == "new":
            return any(n == p or n in p.parents for n in map(Path, self.paths)
                       for p in (repo.gitdir, repo.common, repo.root))
        gitdir, common = Path(self.paths[0]), Path(self.paths[1])
        root = Path(self.paths[2]) if self.paths[2] else None
        roots = set(gitdir_roots(gitdir))
        if common != gitdir:
            roots |= set(gitdir_roots(common))
        if repo.gitdir not in roots or repo.common not in roots:
            return False
        return repo.gitdir != gitdir or root is None or repo.root == root


def _ppid_linux(pid: int) -> int:
    st = Path(f"/proc/{pid}/stat").read_text()
    return int(st[st.rindex(")") + 2:].split()[1])            # state, ppid, …


def _ppid_mac(pid: int) -> int:
    import ctypes
    buf = ctypes.create_string_buffer(136)                    # sizeof(struct proc_bsdinfo)
    if ctypes.CDLL(None).proc_pidinfo(pid, 3, ctypes.c_uint64(0), buf, 136) != 136:   # PROC_PIDTBSDINFO
        raise OSError(f"proc_pidinfo({pid}) failed")
    return int.from_bytes(buf.raw[16:20], sys.byteorder)      # pbi_ppid


def _ancestors() -> set[int]:
    """The pids of this process and its ancestors. Linux: the ppid of
    `/proc/<pid>/stat` (the second field after the command's closing
    parenthesis); macOS: proc_pidinfo(PROC_PIDTBSDINFO), `pbi_ppid` at
    offset 16 of struct proc_bsdinfo (libproc.h). Elsewhere, or where a
    step fails: the chain stops there — a marker from higher up is then no
    marker, fail closed."""
    ppid_of = (_ppid_linux if sys.platform.startswith("linux")
               else _ppid_mac if sys.platform == "darwin" else None)
    out, pid = set(), os.getpid()
    for _ in range(128):
        out.add(pid)
        if pid <= 1:
            break
        try:
            pid = ppid_of(pid) if ppid_of else (os.getppid() if pid == os.getpid() else 0)
        except (OSError, ValueError, IndexError):
            break
    return out


def read_judged() -> Judged | None:
    """The marker of the environment; None without one, or when its process
    is gone (the marker outlived its git: no marker, the user's semantics).
    A malformed one is refused: a child never guesses."""
    v = os.environ.get(JUDGED_ENV)
    if v is None:
        return None
    try:
        pid, _, rest = v.partition(":")
        kind, eq, value = rest.partition("=")
        paths = [os.fsdecode(bytes.fromhex(h)) for h in value.split(",")]
        ok = (kind == "repo" and len(paths) == 3 and paths[0] and paths[1]
              or kind == "new" and 1 <= len(paths) <= 2 and all(paths))
        if not eq or not ok:
            raise ValueError
        j = Judged(int(pid), kind, paths)
    except ValueError:
        raise Refuse(f"malformed {JUDGED_ENV}: {v!r}") from None
    return j if j.alive else None


def set_judged(kind: str, *paths: str) -> None:
    os.environ[JUDGED_ENV] = f"{os.getpid()}:{kind}=" + ",".join(os.fsencode(p).hex() for p in paths)


def check_wrap() -> None:
    """Warn (without refusing) when git's exec path does not lead to
    gitguard: the children of every git then run unwrapped, and a
    repository git enters through one — a submodule, a repository planted
    in the tree — is not judged at entry. The exec path is GIT_EXEC_PATH
    when set, else what the real git answers to `--exec-path`: a run of git
    without a repository (handle_options exits before any setup), the one
    git gitguard runs. Called where the user reads the output: trust,
    retrust, list."""
    p = os.environ.get("GIT_EXEC_PATH")
    if not p:
        import subprocess
        try:
            r = subprocess.run([real_git(), "--exec-path"], capture_output=True, text=True,
                               timeout=10)
            p = r.stdout.strip()
        except (OSError, subprocess.SubprocessError, Refuse):
            p = ""
    me = Path(__file__).resolve()
    try:
        wrapped = bool(p) and (Path(p) / "git").resolve() == me
    except OSError:
        wrapped = False
    if not wrapped:
        how = (f"Debian: `dpkg-divert --package gitguard --add --rename --divert {san(p)}/git.real "
               f"{san(p)}/git && ln -s {me} {san(p)}/git`; elsewhere a GIT_EXEC_PATH directory"
               if p else "see DESIGN-exec-path.md, Installation")
        warn(f"git's exec path ({san(p) or 'unknown'}) does not lead to gitguard: the children "
             f"of every git command run unwrapped, so a repository git enters through one (a "
             f"submodule, a repository planted in the work tree) is not judged at entry. "
             f"{how} (DESIGN-exec-path.md).")


def main(argv: list[str]) -> int:
    mode, yes = "check", False
    name = Path(argv[0]).name
    if name == "git" or name in TRANSPORT:
        mode, argv = "exec", argv[1:]    # invoked through a symlink named git
    elif name.startswith("git-"):
        # `<exec-path>/git-<cmd>` is a symlink to `<exec-path>/git` (Debian:
        # 160 builtins); with gitguard diverted there, a child git or a
        # dashed invocation lands here under that name.
        mode, argv = "exec", [name[4:], *argv[1:]]
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
        direct = passthrough(name, argv)
        if direct is not None:
            git = real_git()
            os.execv(git, [git, *direct])
        newrepo = parse_new_repo(argv)
        orig = apply_global_options(argv)
    # A refusal that nobody will read (exec mode, no controlling terminal) is
    # recorded for `gitguard pending`. The "changed" case records itself
    # (and waits); here the never-trusted and structural ones.
    label: Path = Path.cwd()
    key: Path | None = None
    old: Manifest | None = None
    fingerprinted = False
    judged = read_judged() if mode == "exec" else None       # a child git
    try:
        if mode == "exec":
            git = real_git()             # resolved first: no git at all is its own error
        root = find_root(Path.cwd())
        if root is None:
            if mode == "exec":
                check_archive_outside_repo(split_global_options(argv, orig).rest)
                return run_git(argv, orig, newrepo, git, judged)
            if mode != "check":
                raise Refuse(f"no git repository here: {Path.cwd()}")      # [30]
            return 0
        repo = open_repo(root)
        label, key = repo.label, repo.key
        if judged is not None:
            rest = split_global_options(argv, orig).rest
            covered = judged.covers(repo)
            if os.environ.get("GITGUARD_DEBUG"):
                err(f"child git: marker {judged.kind}={judged.paths}, repository gitdir={repo.gitdir} "
                    f"common={repo.common} root={repo.root} → {'inherits' if covered else 'judges'}")
            if covered:
                # The judged repository: inherited, the command's own writes
                # are for the next command. Not the checks on this child's
                # arguments: a push or an archive --remote is judged on where
                # it goes ([62] [70]) — on that alone: judged under its own
                # key, a submodule's push (`push --recurse-submodules`, an
                # alias `push -u && push --tags`) was refused as never
                # trusted or as changed by the first push. [108]
                if rest[:1] in (["push"], ["archive"]):
                    insp = inspect(repo)
                    check_remote_destination(repo, rest, insp.scan.remote_names, insp.refs)
                return run_git(argv, orig, newrepo, git, judged)
        insp = inspect(repo)
        refs, new = insp.refs, insp.new
        if mode == "exec":
            rest = split_global_options(argv, orig).rest
            check_remote_destination(repo, rest, insp.scan.remote_names, refs)
        old = load_manifest(key)
        fingerprinted = True
    except Refuse as e:
        if mode == "exec" and not e.recorded and (judged is not None or not has_tty()):
            kind = "never" if fingerprinted and (old is None or not old.current) else "structural"
            record_pending(key or key_for(Path.cwd().resolve()), kind, label, str(e),
                           notify_user=judged is None)
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
                check_wrap()
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
        check_wrap()
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
        # A child never asks, waits, auto-accepts or notifies: it shares the
        # parent's terminal, which the parent git may be reading, and nobody
        # is left waiting on it. It refuses at once and records.
        check_or_die(repo, key, old, new, refs, interactive=(mode == "exec" and judged is None))
    except Refuse as e:
        if mode == "exec" and not e.recorded and (judged is not None or not has_tty()):
            kind = "never" if old is None or not old.current else "structural"
            record_pending(key, kind, label, str(e), notify_user=judged is None)
            e.recorded = True
        raise
    if mode == "exec":
        set_judged("repo", str(repo.gitdir), str(repo.common), str(repo.root))
        return run_git(argv, orig, newrepo, git, judged)
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
