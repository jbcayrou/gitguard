#!/usr/bin/env python3
"""Inventory of what git reads and runs, taken from git's own source.

    python3 tests/inventory.py <git source tree>  >  tests/inventory/git-<ver>.txt

gitguard's closed lists (VOLATILE_*, DIR_KEYS, DATA_KEYS, GLOBAL_FLAGS…) are
claims about git. The bypass catalogue grew one case at a time because the
universe those lists live in was never written down; git's source names it
under a handful of signatures. This script extracts them; test_claims.py
holds gitguard's lists to the latest snapshot in tests/inventory/, so that
an item git knows and gitguard has not classified fails there, before a
review finds it. On a git upgrade: regenerate, diff the two snapshots,
classify what is new.

Sections (one item per line, `# ` comments, blank lines ignored):

  [gitdir]    names git opens under a gitdir: GIT_PATH_FUNC and the literal
              arguments of repo_git_path/git_path (printf patterns dropped).
  [pathname]  config keys read through git_config_pathname /
              *_config_get_pathname: a value that is a path git opens.
  (no [program] section: a key whose value git runs has no single signature
  in the source and the documentation phrases it a dozen ways; that list is
  curated by hand, test_claims.py PROGRAM_KEYS, from Documentation/config.)
  [hooks]     hook names, from Documentation/githooks.adoc.
  [options]   git's global options, from git.c.

Extraction is by regular expression over C and AsciiDoc: good enough to be
complete on what it targets, reviewed by eye at each regeneration (the
section comments say where each pattern can miss).
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

def c_files(src: Path, suffix: str = "*.c") -> list[Path]:
    """git's sources without its test suite (`t/`): a filter on the first
    path component only — `"t/" in path` also dropped `compat/`, and with it
    the fsmonitor socket."""
    return sorted(p for p in src.rglob(suffix) if p.relative_to(src).parts[0] != "t")


def gitdir_names(src: Path) -> set[str]:
    """GIT_PATH_FUNC(fn, "name") in .c/.h, and repo_git_path(r, "name") /
    git_path("name") literals. A name with a printf pattern (`%s`) is a
    family (lost-found/%s/%s, sharedindex.%s): kept with the pattern."""
    out: set[str] = set()
    pat_func = re.compile(r'GIT_PATH_FUNC\(\w+,\s*"([^"]+)"')
    pat_call = re.compile(r'(?:repo_)?git_path(?:dup)?\(\s*(?:[\w>.-]+,\s*)?"([^"]+)"')
    for p in c_files(src) + c_files(src, "*.h"):
        text = p.read_text(errors="replace")
        out.update(pat_func.findall(text))
        out.update(pat_call.findall(text))
    out.discard("FOO")                                   # path.c's own example
    return {n for n in out if re.search(r"[A-Za-z0-9]", n) and not n.startswith("%")}


def pathname_keys(src: Path) -> set[str]:
    """The key compared just before each git_config_pathname(): the closest
    strcmp above the call, within the same if/else chain (one key per
    call; a chain `if (!strcmp(...)) return git_config_pathname(...)` gives
    its own key for each return). Plus the literal key of
    git_config_get_pathname / repo_config_get_pathname."""
    out: set[str] = set()
    key_re = re.compile(r'"([a-zA-Z][\w]*\.[\w.<>*-]+)"')
    for p in c_files(src):
        lines = p.read_text(errors="replace").splitlines()
        for i, line in enumerate(lines):
            if "git_config_pathname(" in line and "define" not in line:
                for j in range(i, max(i - 8, -1), -1):
                    if "strcmp" in lines[j] or "skip_prefix" in lines[j]:
                        out.update(k.lower() for k in key_re.findall(lines[j]))
                        break
            m = re.search(r'config_get_pathname\(\s*(?:[\w>.-]+,\s*)?"([^"]+)"', line)
            if m:
                out.add(m.group(1).lower())
    return out


def hooks(src: Path) -> list[str]:
    """Section titles of githooks.adoc (a name over a `~~~` underline)."""
    lines = (src / "Documentation" / "githooks.adoc").read_text().splitlines()
    return [lines[i - 1] for i, l in enumerate(lines)
            if re.fullmatch(r"~{3,}", l) and re.fullmatch(r"[a-z0-9-]+", lines[i - 1])]


def global_options(src: Path) -> set[str]:
    """Options handle_options() in git.c compares `cmd` to."""
    text = (src / "git.c").read_text()
    out = set(re.findall(r'!strcmp\(cmd, "(--?[\w-]+)"\)', text))
    out.update(o.rstrip("=") for o in re.findall(r'skip_prefix\(cmd, "(--[\w-]+=?)"', text))
    return out


def version(src: Path) -> str:
    """DEF_VER of GIT-VERSION-GEN (the release line) and the commit."""
    m = re.search(r"DEF_VER=v?([\w.]+)", (src / "GIT-VERSION-GEN").read_text())
    r = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=src,
                       capture_output=True, text=True)
    return f"{m.group(1) if m else 'unknown'} ({r.stdout.strip() or 'no commit'})"


def main() -> None:
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    src = Path(sys.argv[1])
    print(f"# git {version(src)}, generated by tests/inventory.py")
    print("\n[gitdir]")
    print("\n".join(sorted(gitdir_names(src))))
    print("\n[pathname]")
    print("\n".join(sorted(pathname_keys(src))))
    print("\n[hooks]")
    print("\n".join(hooks(src)))
    print("\n[options]")
    print("\n".join(sorted(global_options(src))))


if __name__ == "__main__":
    main()
