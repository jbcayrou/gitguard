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

## You are not the only one running git

An alias protects the `git` you type. It does not protect the git that runs
because you merely *looked* at the repository:

- **Shell prompts.** oh-my-zsh, powerlevel10k, Starship, `git-prompt.sh` run
  `git status`, `git rev-parse`, `git symbolic-ref` at every prompt, and
  oh-my-zsh does it with `command git`, which skips aliases by design. A
  `core.fsmonitor` planted in `.git/config` fires the moment you `cd` into
  the directory, before you have typed a single git command.
- **Editors.** VS Code's git extension runs `git status` every few seconds
  and `git fetch` periodically (`git.autofetch`); JetBrains, magit, lazygit,
  tig, fugitive do the same on their own schedule. Opening the folder is
  enough.
- **Build tooling.** Makefiles, `setuptools_scm`, `go build` with VCS
  stamping, npm `prepare` scripts, pre-commit, husky, git-lfs call `git` by
  name and never see your alias.

Which git each of these finds depends on the `PATH` it was started with, not
on your shell's aliases. That is why the install below puts gitguard **as
`git`** in a directory ahead of the real one: everything that resolves `git`
through the `PATH` is then wrapped — prompts, `command git`, scripts, and
editors started from a shell (VS Code resolves your login shell's
environment at startup, even when launched from the Dock).

Still outside: a tool with a hardcoded `/usr/bin/git`, a GUI started by a
launcher with a minimal `PATH`, and the git that hooks or `rebase --exec`
run (the real git puts its own exec path first). For VS Code, set `git.path`
to the gitguard symlink to remove the doubt. Tools built on libgit2 rather
than the git binary do not run hooks or config commands and are outside this
picture.

Cost: one check per invocation, ~45 ms; a prompt that calls git three times
pays ~150 ms. In a repository you have not trusted, or whose trusted files
changed, those calls are refused: the prompt shows no git information until
you run `gitguard trust`. That silence is the signal.

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

Then put a symlink named `git` in a directory ahead of the real git in your
`PATH` (gitguard detects it is called `git` and switches to exec mode). This
also covers the tools that run git for you, see above:

```sh
ln -s ~/bin/gitguard ~/bin/git
```

If you only want the `git` you type wrapped, an alias is enough:

```sh
alias git='gitguard git'
```

### System-wide (Debian/Ubuntu)

To wrap every git on the machine, cron and GUIs included, install gitguard
*as* `/usr/bin/git` and divert the real one. `dpkg-divert` keeps the
diversion across `apt upgrade git`:

```sh
sudo install -m 755 gitguard.py /usr/bin/gitguard
sudo dpkg-divert --package gitguard --add --rename --divert /usr/bin/git.real /usr/bin/git
sudo ln -s gitguard /usr/bin/git
```

gitguard finds a `git.real` next to itself without any environment variable.
Hooks and `rebase --exec` run by the real git use `/usr/lib/git-core/git`,
unwrapped by design. Repositories that already exist get one `gitguard
trust` each, after you have looked at them; new ones are trusted at `clone`
/ `init`. To undo:

```sh
sudo rm /usr/bin/git
sudo dpkg-divert --package gitguard --rename --remove /usr/bin/git
```

On macOS `/usr/bin/git` is protected by SIP and renaming Homebrew's git is
undone by `brew upgrade`: keep the `PATH` symlink (it covers everything
started from a login shell, VS Code included) and set `git.path` in VS Code.

Contexts without a terminal (cron, CI, scripts) get no `[y/N]` question: a
never-trusted or changed repository is refused there. Have the script run
`gitguard trust` after its `remote add` / `worktree add`, or call the real
git if the repository is not exposed to a sandbox.

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
| `GITGUARD_REAL_GIT` | Path to the real git (default: a `git.real` next to gitguard, else the first `git` in the PATH that is not gitguard itself). |
| `GITGUARD_ALLOW_REBASE_EXEC=1` | Allow `exec` lines in rebase todo files. |
| `GITGUARD_NO_PROMPT=1` | Never ask on the terminal; refuse directly. |
| `GITGUARD_DEBUG=1` | Full traceback on internal errors. |
| `NO_COLOR` | Disable colours. |

## What it does not do

- It only covers git invocations that resolve to the wrapper. A tool with a
  hardcoded path to the real git, or started with a `PATH` that does not
  contain the symlink, is not checked (see "You are not the only one running
  git").
- The `[y/N]` question needs stdout and stderr on a terminal. A shell
  prompt's `$(git …)` or a `git log | head` on a changed repository is
  refused, not asked: rerun without the pipe, or `gitguard trust`.
- It cannot close the race between its check and git's execution if the
  sandbox is still writing. Stop the sandbox before running git on the host.
- `restore` only cleans the pivot vector: objects, commits and tree files
  dropped by the sandbox stay there for you to inspect.
- Bare repositories are refused, not managed.
- Parity with git is checked against git itself in `tests/test_git_parity.py`;
  a gap found there is marked as an expected failure until fixed (none open
  at the moment). Deliberate, fail-closed divergences: a NUL byte or a line
  git dies on in a config file is refused.

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
