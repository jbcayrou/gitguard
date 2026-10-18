# Performance

Overhead of `gitguard git <cmd>` over a plain `git <cmd>`, measured on
2026-10-17 at commit `73b0d1c`.

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

| command          | git     | gitguard git | overhead | `GITGUARD_SCAN_TREE=1` |
|------------------|--------:|-------------:|---------:|-----------------------:|
| `status`         | 247 ms  | 293 ms       | +46 ms   | +211 ms                |
| `log -1`         |   6 ms  |  52 ms       | +46 ms   | +212 ms                |
| `rev-parse HEAD` |   4 ms  |  49 ms       | +45 ms   | +210 ms                |
| `diff --stat`    | 125 ms  | 172 ms       | +48 ms   | +217 ms                |
| `branch`         |   5 ms  |  50 ms       | +45 ms   | +212 ms                |

`gitguard` alone (check, no git): 49 ms.

Index cache invalidated (`<key>.idx` removed, i.e. right after a command
that rewrote the 10 MB index): check at 80–90 ms instead of 45 ms, once;
the next command is back to 45 ms.

## Small repository (gitguard itself)

~30 files. N = 15.

| command          | git   | gitguard git | overhead | `GITGUARD_SCAN_TREE=1` |
|------------------|------:|-------------:|---------:|-----------------------:|
| `status`         | 5 ms  | 48 ms        | +43 ms   | +41 ms                 |
| `log -1`         | 5 ms  | 46 ms        | +40 ms   | +41 ms                 |
| `rev-parse HEAD` | 4 ms  | 45 ms        | +41 ms   | +41 ms                 |
| `diff --stat`    | 4 ms  | 45 ms        | +41 ms   | +41 ms                 |
| `branch`         | 5 ms  | 45 ms        | +41 ms   | +41 ms                 |

`gitguard` alone: 45 ms.

## Where the time goes

| component                                             | cost            |
|-------------------------------------------------------|----------------:|
| Python startup + stdlib imports (`python floor`)      | 32 ms           |
| gitguard's own work on a small repository             | ~13 ms          |
| extra on the kernel (gitdir hashing, `.idx` read)     | ~4 ms           |
| index re-parse when the index changed (10 MB, cached) | +40 ms, once    |
| tree scan, `GITGUARD_SCAN_TREE=1` (6 285 directories) | +165 ms         |
| config parser (port of git's config.c), 17 KB config  | ~2 ms           |

Conclusions:

- The overhead is a constant ~45 ms per command, independent of the
  repository size; 70 % of it is the interpreter's startup. A compiled
  rewrite would bring it to a few ms, and would change nothing for the
  tree scan, which is bound by `readdir` (APFS serialises it; a C `find`
  was measured slower, 8 threads 3× slower).
- The tree scan (`GITGUARD_SCAN_TREE`, +210 ms on the kernel for an early
  warning only) was removed the day after these measurements; the column is
  kept as the record of why (see CLAUDE.md, "Nested repositories").
- The config parser is invisible at this scale.

## Reproducing

```python
"""Raw git vs gitguard git on a repository. Median of N runs, ms."""
import os, statistics, subprocess, sys, time
repo, n = sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 15
GG = os.path.abspath("gitguard.py")
GIT = "/opt/homebrew/bin/git"
state = os.path.abspath("bench-state")
env = dict(os.environ, GITGUARD_REAL_GIT=GIT, GITGUARD_STATE=state, NO_COLOR="1")

def run(cmd, extra=None):
    e = dict(env, **(extra or {}))
    ts = []
    for _ in range(n):
        t = time.perf_counter()
        r = subprocess.run(cmd, cwd=repo, env=e, capture_output=True)
        ts.append((time.perf_counter() - t) * 1000)
        assert r.returncode == 0, (cmd, r.stderr[-500:])
    return statistics.median(ts)

subprocess.run([sys.executable, GG, "trust"], cwd=repo, env=env, capture_output=True, check=True)
cases = [("status", ["status"]), ("log -1", ["log", "-1"]), ("rev-parse HEAD", ["rev-parse", "HEAD"]),
         ("diff --stat", ["diff", "--stat"]), ("branch", ["branch"])]
print(f"{'command':16} {'git':>10} {'gitguard git':>14} {'overhead':>10} {'+scan tree':>12}")
for name, args in cases:
    raw = run([GIT, *args])
    gg = run([sys.executable, GG, "git", *args])
    sc = run([sys.executable, GG, "git", *args], {"GITGUARD_SCAN_TREE": "1"})
    print(f"{name:16} {raw:8.0f}ms {gg:12.0f}ms {gg - raw:+8.0f}ms {sc - raw:+10.0f}ms")
print(f"{'gitguard (check)':16} {'':>10} {run([sys.executable, GG]):12.0f}ms")
floor = run([sys.executable, "-c", "import difflib,hashlib,json,os,re,shlex,shutil,stat,subprocess,sys,time,dataclasses,functools,pathlib"])
print(f"{'python floor':16} {'':>10} {floor:12.0f}ms")
```

Run from the gitguard checkout: `python3 bench.py <repo> [N]`. For the
kernel: `git clone --depth 1
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git`
(a few minutes, 2 GB; the GitHub mirror may hang on `info/refs`).
