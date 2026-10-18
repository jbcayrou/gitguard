# gitguard

A guard that refuses to run `git` on a repository whose trusted files
(`.git/config`, hooks, attributes, alternates, nested gitfiles, hook
directories named by the config…) have changed since you last validated them.

Single Python 3 file, standard library only, no dependencies.

## The problem

You run untrusted code — an LLM coding agent, a container with a bind mount,
a CI job, a third-party build tool — with write access to a directory that
holds git repositories. Writing into the work tree is the whole point, and
`.git/` sits inside it. Malicious code there can drop a hook, add
`core.fsmonitor = /tmp/evil` to `.git/config`, redirect `.git` to a
booby-trapped directory, plant a nested repository… The next time *you* run
`git` on the host, that code runs with your rights: SSH keys, credentials,
shell. That is the sandbox-to-host pivot.

Sandboxing layers (AppArmor/seccomp profiles, `core.hooksPath` set globally,
`safe.bareRepository=explicit`, rootless uid mapping) prevent some of it.
gitguard **detects** the rest: it refuses to run git until you have looked.

## How it works

- `gitguard trust` records a **fingerprint** of everything in `.git/` except
  what git rewrites during normal operation (objects, refs, logs, index…),
  plus the tree files that drive git (`.gitmodules`, `.lfsconfig`, nested
  gitfiles) and every path the config makes git execute or read
  (`core.hooksPath`, `include.path` chains, scripts named in aliases and
  filters). The global and system configs are parsed and hashed too.
- Every later `git` invocation is checked against that fingerprint first.
  Any deviation, structural anomaly (symlinked `.git`, bare gitdir planted in
  a subdirectory, `exec` lines injected into a rebase todo, control
  characters in names…) or unknown repository → git is not run.
- The fingerprint lives in `~/.local/state/gitguard/`, outside any mounted
  volume, with a backup of the watched files so `gitguard restore` can put
  them back.

It is a fingerprint, not a blocklist of "dangerous" config keys: there is
nothing to keep up to date with git's CVEs. The price is an explicit
`gitguard trust` when *you* change your hooks or config. Pure branch-tracking
changes (`push -u`, `branch -u`) are recognised and accepted automatically;
anything else shows a diff and asks on the terminal.

## Install

```sh
install -m 755 gitguard.py ~/bin/gitguard
```

Then either wrap git in your shell:

```sh
alias git='gitguard git'
```

or put a symlink named `git` ahead of `/usr/bin` in your `PATH` (gitguard
detects it is called `git` and switches to exec mode):

```sh
ln -s ~/bin/gitguard ~/bin/git
```

Recommended companion setting, independent of gitguard:

```sh
git config --global safe.bareRepository explicit
```

Then, in each repository you work on:

```sh
gitguard trust
```

Successful `git clone` / `git init` through the wrapper are trusted
automatically.

## Commands

| Command | What it does |
|---|---|
| `gitguard` | Check the current repository. Exit 1 if suspect or never trusted. |
| `gitguard trust` | Record the current state as the reference, with a backup of the watched files. |
| `gitguard diff` | Show what differs from the reference. |
| `gitguard restore [-y]` | Put the watched files back into the reference state. |
| `gitguard git <args>` | Check, then run the real git. Honours `-C`, `--git-dir`, `--work-tree`. |
| `gitguard list` | Registered repositories and their status. |
| `gitguard forget <repo>…` / `--missing` | Remove entries. |
| `gitguard prune` | Same as `forget --missing`. |
| `gitguard retrust` | Re-validate unchanged repositories after an upgrade. |

## Environment variables

| Variable | Effect |
|---|---|
| `GITGUARD_STATE` | State directory (default `~/.local/state/gitguard`). |
| `GITGUARD_REAL_GIT` | Path to the real git (default: the first `git` in the PATH that is not gitguard itself). |
| `GITGUARD_ALLOW_REBASE_EXEC=1` | Allow `exec` lines in rebase todo files. |
| `GITGUARD_NO_PROMPT=1` | Never ask on the terminal; refuse directly. |
| `GITGUARD_DEBUG=1` | Full traceback on internal errors. |
| `NO_COLOR` | Disable colours. |

## What it does not do

- It only covers git invocations that go through the wrapper or alias. An
  IDE or another tool calling git directly is not checked.
- It cannot close the race between its check and git's execution if the
  sandbox is still writing. Stop the sandbox before running git on the host.
- `restore` only cleans the pivot vector: objects, commits and tree files
  dropped by the sandbox stay there for you to inspect.
- Bare repositories are refused, not managed.
- Known parity gaps with git (config set through the environment,
  `core.worktree`, `~user/` expansion, shell operators inside `!` aliases)
  are documented as expected failures in `tests/test_git_parity.py`.

See `CLAUDE.md` for the full design notes, the review method and the
catalogue of bypasses found so far (`tests/attacks/`).

## Tests

```sh
python3 -m pytest
```

Needs `pytest` and `git`. The suite replays a corpus of attacks against a
trusted repository and checks that each one is refused, and that ordinary git
operations are not.

## License

MIT — see `LICENSE`.
