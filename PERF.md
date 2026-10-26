# Performance

Overhead of `gitguard git <cmd>` over a plain `git <cmd>`, measured on
2026-10-17 at commit `73b0d1c`.

Re-checked on 2026-10-19 with the current code (pending decisions, real git
resolved from the PATH): same overhead within 3 ms on the small repository,
head to head against the `73b0d1c` script on the same machine state. The
tables below are the original measurements.

Re-checked on 2026-10-25 after the fixes of [86]–[99] (global values read
again in each submodule, hard-link and FIFO checks, sparse directories):
`gitguard` alone, median of 25, against the previous commit on the same
machine state — 39.4 → 40.4 ms on a one-file repository, 62.5 → 64.9 ms on
one with 10 submodules and a global config of 30 aliases and a config hook.

## Child gits (DESIGN-exec-path.md)

With gitguard at git's exec path, every child git is gitguard too. On the
Debian VM (git 2.47.3, python 3.13), a trusted one-file repository, the
same gitguard as parent and child, median of 15 (2026-10-26):

| command                          | raw children | wrapped children |
|----------------------------------|-------------:|-----------------:|
| `log -1` (no child)              | 26 ms        | 26 ms            |
| `commit` (one child: maintenance)| 26 ms        | 50 ms            |
| alias `!git log` (one child)     | 26 ms        | 50 ms            |
| alias with three children        | 27 ms        | 101 ms           |

About 25 ms per child on the VM: the interpreter's start (the inheriting
child skips the check itself). `pull` has two or three children, `status`
one per submodule, `submodule foreach` one per submodule plus the command's.

## Environment

- Apple M4 Pro, macOS (Darwin 27.0), APFS
- git 2.50.0 (Homebrew), used both directly and as `GITGUARD_REAL_GIT`
- Python 3.14 (Homebrew), gitguard.py stdlib only
- Isolated state directory (`GITGUARD_STATE`), repository trusted before
  the measurements, `NO_COLOR=1`
- Median of N runs per command (`subprocess.run` from Python, process
  start included)

## Linux kernel (shallow clone)

`git clone --depth 1` of torvalds/linux from kernel.org: 96 080 tracked
files, 6 285 directories, ~10 MB index. N = 10.

| command          | git     | gitguard git | overhead |
|------------------|--------:|-------------:|---------:|
| `status`         | 247 ms  | 293 ms       | +46 ms   |
| `log -1`         |   6 ms  |  52 ms       | +46 ms   |
| `rev-parse HEAD` |   4 ms  |  49 ms       | +45 ms   |
| `diff --stat`    | 125 ms  | 172 ms       | +48 ms   |
| `branch`         |   5 ms  |  50 ms       | +45 ms   |

`gitguard` alone (check, no git): 49 ms.

Index cache invalidated (`<key>.idx` removed, i.e. right after a command
that rewrote the 10 MB index): check at 80–90 ms instead of 45 ms, once;
the next command is back to 45 ms. Since [55] the same parse also checks
every entry name (port of git's verify_path): +30 ms on 96k synthetic
kernel-like names (ten substring scans of the 2.6 MB joined names, the
full port only on the names they flag), so ~110–120 ms once after an
index rewrite, cached afterwards.

## Small repository (gitguard itself)

~30 files. N = 15.

| command          | git   | gitguard git | overhead |
|------------------|------:|-------------:|---------:|
| `status`         | 5 ms  | 48 ms        | +43 ms   |
| `log -1`         | 5 ms  | 46 ms        | +40 ms   |
| `rev-parse HEAD` | 4 ms  | 45 ms        | +41 ms   |
| `diff --stat`    | 4 ms  | 45 ms        | +41 ms   |
| `branch`         | 5 ms  | 45 ms        | +41 ms   |

`gitguard` alone: 45 ms.

### Same on Linux (Debian 13, VM)

Debian 13 aarch64 in a VM on the same machine, ext4, Python 3.13.5
(system), git 2.47.3, system-wide install (`/usr/bin/git → gitguard`, real
git at `git.real`). Small repository, N = 20, 2026-10-19.

| command          | git   | gitguard git | overhead |
|------------------|------:|-------------:|---------:|
| `status`         | 1 ms  | 27 ms        | +26 ms   |
| `log -1`         | 0 ms  | 27 ms        | +26 ms   |
| `rev-parse HEAD` | 0 ms  | 26 ms        | +26 ms   |

`gitguard` alone: 29 ms; Python floor 16 ms. Same shape as macOS: the
interpreter's startup is most of it, Linux starts it twice as fast.

## 2026-10-21: imports trimmed

Same machine, small repository, N = 60, `rev-parse HEAD`: overhead 44 ms →
33 ms. The modules only `trust`, `restore`, `pending` and the prompt need
(`subprocess`, `shutil`, `difflib`, `termios`, `fcntl`, `dataclasses` — the
last one pulls `inspect`) are imported where used; the four former
dataclasses are written out. Import floor of the top-level modules 34 → 22
ms (bare interpreter 16.5 ms).

What remains, measured apart: bare interpreter 16 ms, imports 6 ms,
**compiling gitguard.py 15 ms** — a script run by path is compiled on every
run, only an imported module gets a cached `.pyc` —, gitguard's own work
~2 ms. A two-file layout (a three-line launcher importing the module, whose
`.pyc` is cached) measured 25.6 ms against 37.3 ms for the script, i.e.
overhead 21 ms. `python3 -S` (no `site`) saves 5 ms on `python3 -c pass`
but under 1 ms on a gitguard command: not worth an `env -S` shebang.

Re-measured on 2026-10-22, both versions head to head, small repository,
N = 30, all five commands within 0.5 ms of each other:

| machine                          | before  | after   | `python3 -c pass` |
|----------------------------------|--------:|--------:|------------------:|
| macOS, M4 Pro, Python 3.14.6     | +46 ms  | +35 ms  | 15 ms             |
| Debian 13 VM, aarch64, Python 3.13.5 | +27 ms | +20 ms | 4 ms             |

`gitguard` alone: 50 → 37 ms on macOS, 30 → 22 ms on the VM.

## 2026-10-22: fixes [58]–[65]

`gitguard` alone (plain check), before and after the fixes of [58]–[65],
head to head, N = 30, median; the A/B script is under "Reproducing":

| machine, repository                        | before  | after   |
|--------------------------------------------|--------:|--------:|
| macOS, small repository (gitguard itself)  | 38.0 ms | 39.5 ms |
| macOS, 40 shell aliases in the config      | 47.9 ms | 41.8 ms |
| Debian VM, small repository                | 22.0 ms | 23.1 ms |
| Debian VM, 40 shell aliases in the config  | 28.5 ms | 26.1 ms |

The +1 ms on a small repository: a longer script to compile, the
repository format read once more for the index (`object_id_size`, [63]),
the submodules' trees ([60]). The sh readings of [58] add tokens, and
every token cost a `resolve()`: an alias-heavy config produced 1248
tokens for 35 distinct ones. Resolved once per base now, which more than
pays for the readings.

## 2026-10-23: fixes [66]–[70], [72], [73], [75], [76]

`gitguard` alone (plain check), `ca23feb` (the previous measurement) against
`606c09e`, head to head, N = 60, median, two rounds each (the A/B script
under "Reproducing"):

| machine, repository                        | before  | after   |
|--------------------------------------------|--------:|--------:|
| macOS, small repository (gitguard itself)  | 40.4 ms | 41.4 ms |
| macOS, 40 shell aliases in the config      | 42.8 ms | 43.5 ms |
| Debian VM, small repository                | 30.0 ms | 30.7 ms |
| Debian VM, 40 shell aliases in the config  | 29.9 ms | 30.7 ms |

+0.7 to +1 ms. Compiling the script accounts for most of it: 153 → 164 KB,
12.7 → 13.5 ms (macOS, median of 30 `compile()`). The rest is a handful
of `stat` calls: the remote's gitdir as a second base for global
`core.hooksPath` ([68]), the symlink chain of a config path ([75]), and
reading `alias.*` values for the command word ([66]) — shell aliases return
at the first character. Absolute figures differ from the 2026-10-22 table
(machine state, the VM's load); only the head-to-head column pair is
comparable.

## 2026-10-24: design review follow-ups ([84], [85], the default switch, ConfigScan)

`gitguard` alone (plain check), `28309e3` (before the four commits of the
review) against the working tree after them, head to head, N = 60,
median, two rounds each, macOS, small repository (a clone of gitguard):

| round | before  | after   |
|-------|--------:|--------:|
| 1     | 44.5 ms | 44.5 ms |
| 2     | 44.8 ms | 44.7 ms |

Unchanged. The script grew 177 → 180 KB (ConfigScan's and
_core_worktree's docstrings) and lost the Levenshtein port; the check
does the same stat calls as before, in the same order (`inspect` only
names the pipeline). Not measured on the Debian VM (down that day).

## Where the time goes (2026-10-17 figures)

| component                                             | cost            |
|-------------------------------------------------------|----------------:|
| Python startup + stdlib imports (`python floor`)      | 32 ms           |
| gitguard's own work on a small repository             | ~13 ms          |
| extra on the kernel (gitdir hashing, `.idx` read)     | ~4 ms           |
| index re-parse when the index changed (10 MB, cached) | +40 ms, once    |
| entry-name check on that re-parse (verify_path, [55])  | +30 ms, once    |
| config parser (port of git's config.c), 17 KB config  | ~2 ms           |

Conclusions:

- The overhead is a constant ~45 ms per command, independent of the
  repository size; 70 % of it is the interpreter's startup. A compiled
  rewrite would bring it to a few ms.
- The config parser is invisible at this scale.
- Nothing walks the work tree. An opt-in tree scan (`GITGUARD_SCAN_TREE`,
  looking for undeclared nested `.git`) existed when these measurements
  were taken: +210 ms on the kernel, +165 ms of it in `readdir` (APFS
  serialises it; a C `find` was slower, 8 threads 3× slower), for an early
  warning the gitlink check already gives. It was removed on 2026-10-18;
  see DESIGN.md, "Nested repositories".

## Reproducing

```python
"""Raw git vs gitguard git on a repository. Median of N runs, ms."""
import os, statistics, subprocess, sys, time
repo, n = sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 15
GG = os.path.abspath("gitguard.py")
GIT = "/opt/homebrew/bin/git"
state = os.path.abspath("bench-state")
env = dict(os.environ, GITGUARD_REAL_GIT=GIT, GITGUARD_STATE=state, NO_COLOR="1")

def run(cmd):
    ts = []
    for _ in range(n):
        t = time.perf_counter()
        r = subprocess.run(cmd, cwd=repo, env=env, capture_output=True)
        ts.append((time.perf_counter() - t) * 1000)
        assert r.returncode == 0, (cmd, r.stderr[-500:])
    return statistics.median(ts)

subprocess.run([sys.executable, GG, "trust"], cwd=repo, env=env, capture_output=True, check=True)
cases = [("status", ["status"]), ("log -1", ["log", "-1"]), ("rev-parse HEAD", ["rev-parse", "HEAD"]),
         ("diff --stat", ["diff", "--stat"]), ("branch", ["branch"])]
print(f"{'command':16} {'git':>10} {'gitguard git':>14} {'overhead':>10}")
for name, args in cases:
    raw = run([GIT, *args])
    gg = run([sys.executable, GG, "git", *args])
    print(f"{name:16} {raw:8.0f}ms {gg:12.0f}ms {gg - raw:+8.0f}ms")
print(f"{'gitguard (check)':16} {'':>10} {run([sys.executable, GG]):12.0f}ms")
floor = run([sys.executable, "-c", "import difflib,hashlib,json,os,re,shlex,shutil,stat,subprocess,sys,time,dataclasses,functools,pathlib"])
print(f"{'python floor':16} {'':>10} {floor:12.0f}ms")
```

Run from the gitguard checkout: `python3 bench.py <repo> [N]`. A/B of two copies of the script (the "before
and after" tables), from the repository to measure:

```python
"""A/B of `gitguard` (plain check) for two copies of gitguard.py, in the cwd's
repository, isolated state. usage: ab.py old.py new.py [N]"""
import os, statistics, subprocess, sys, tempfile, time
old, new = sys.argv[1], sys.argv[2]
n = int(sys.argv[3]) if len(sys.argv) > 3 else 30
env = {**os.environ, "GITGUARD_STATE": tempfile.mkdtemp(), "GITGUARD_NO_NOTIFY": "1"}
for name, path in [("before", old), ("after", new)] * 2:
    subprocess.run([sys.executable, path, "trust"], env=env, capture_output=True)
    ts = []
    for _ in range(n):
        t = time.perf_counter()
        r = subprocess.run([sys.executable, path], env=env, capture_output=True)
        ts.append(time.perf_counter() - t)
    print(f"{name:7} rc={r.returncode} median {statistics.median(ts) * 1000:.1f} ms")
```

`old.py` from `git show <commit>:gitguard.py`. For the
kernel: `git clone --depth 1
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git`
(a few minutes, 2 GB; the GitHub mirror may hang on `info/refs`).
