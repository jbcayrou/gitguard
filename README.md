# gitguard

Refuses to run `git` on a repository whose trusted files (`.git/config`,
hooks, `.gitmodules`, gitfiles, every path the config makes git execute…)
have changed since you last looked at them.

One Python file, standard library only. Linux and macOS, Python ≥ 3.9.

## The problem

You run untrusted code in a container or VM with a host directory mounted
into it, and that directory holds git repositories. The sandbox may be a CI
job, a build of a project you just cloned, a third-party tool, an LLM coding
agent. Writing into the work tree is the whole point, and `.git/` sits
inside it. Malicious code there can drop a hook, add
`core.fsmonitor = /tmp/evil` to `.git/config`, redirect `.git` to a
booby-trapped directory, plant a nested repository… The next time *you* run
`git` on the host, that code runs with your rights: SSH keys, credentials,
shell. That is the sandbox-to-host pivot.

Sandboxing layers (AppArmor/seccomp profiles, a global `core.hooksPath`,
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

Cost: one check per invocation, ~33 ms, whatever the size of the tree
(see `PERF.md`). A prompt that calls git three times pays ~100 ms. In a
repository you have not trusted, or whose trusted files changed, those calls
are refused: the prompt shows no git information until you have decided.
That silence is the signal.

## How it works

`gitguard trust` records a **fingerprint** of:

- everything in `.git/`, at any depth, `modules/` and `worktrees/` included,
  except what git rewrites in normal operation (objects, refs, logs, index,
  `*_HEAD`…). An unknown file is watched, not ignored;
- the tree files that drive git: `.gitmodules`, `.lfsconfig`, the gitfile of
  each submodule or linked worktree;
- every path the config makes git execute or read: `core.hooksPath`,
  `include.path` chains, scripts named in aliases, filters, drivers,
  `credential.helper`… — in the tree or outside it, as long as you could
  write there (a `core.hooksPath` resolving to the root of the tree is
  refused: every top-level file would be a hook);
- a local remote (`remote.*.url` = a path in the volume): the config and
  hooks of the repository `push` enters, opened as git opens it; `git push
  <path>` to a repository no remote names is refused;
- the paths named by the system and global configs: a global
  `core.hooksPath` pointing into the mounted volume is a bypass otherwise
  (the files themselves are parsed, not hashed: the sandbox cannot write
  them). Files git reads as data — a signing key, `commit.template`,
  `core.excludesFile` — are not watched; a file outside the repository named
  by a program key is watched but never copied into the state directory.

Every later `git` invocation is checked against that fingerprint first. Any
deviation, structural anomaly (symlinked `.git`, bare gitdir planted in a
subdirectory, undeclared nested repository, `exec` lines injected into a
rebase todo, an index entry whose name escapes the work tree — `.git/hooks/x`,
`../x`, which `checkout -- .` and `restore` would write as is —, control
characters in names…) or unknown repository → git is not run. The config is parsed by a port of git's own parser, never by
calling `git config`: git would honour the config being judged.

The fingerprint lives in `~/.local/state/gitguard/`, outside any mounted
volume, with a backup of the watched files so `gitguard restore` can put
them back.

It is a fingerprint, not a blocklist of "dangerous" config keys: there is
nothing to keep up to date with git's CVEs, and no key it can miss. The
price is an explicit `gitguard trust` when *you* change your hooks, remotes
or config; see "Day to day" for how much of that is automated.

## Install

```sh
install -m 755 gitguard.py ~/bin/gitguard
ln -s ~/bin/gitguard ~/bin/git      # a directory ahead of the real git in your PATH
```

gitguard detects it is called `git` and switches to exec mode. The real git
is the first `git` of the `PATH` that is not gitguard itself (or
`GITGUARD_REAL_GIT`). If you only want the `git` you type wrapped, an alias
is enough, with the limits described above:

```sh
alias git='gitguard git'
```

### System-wide (Debian/Ubuntu)

To wrap every git on the machine, cron and GUIs included, install gitguard
*as* `/usr/bin/git` and divert the real one — and do the same at git's
**exec path**, `/usr/lib/git-core/git`: that is the `git` every git runs
its children through (`git status` in a submodule, `git pull` in a hook,
the `index-pack` of a clone), and the wrap is what lets a child judge the
repository it enters (DESIGN-exec-path.md). `dpkg-divert` keeps both
diversions across `apt upgrade git`:

```sh
sudo install -m 755 gitguard.py /usr/bin/gitguard
sudo dpkg-divert --package gitguard --add --rename --divert /usr/bin/git.real /usr/bin/git
sudo ln -s gitguard /usr/bin/git
sudo dpkg-divert --package gitguard --add --rename --divert /usr/lib/git-core/git.real /usr/lib/git-core/git
sudo ln -s /usr/bin/gitguard /usr/lib/git-core/git
```

gitguard runs a `git.real` found next to the name it was invoked by
before looking at the `PATH`, so no environment variable is needed (cron,
systemd and GUIs would not get one). The 160 dashed builtins of
`/usr/lib/git-core` (`git-status`, `git-receive-pack`…) are symlinks to
`git` and land on gitguard too: invoked under a dashed name it runs that
command; under `git-receive-pack`, `git-upload-pack` and
`git-upload-archive` (sshd, for every push and fetch *to* the machine) it
passes straight to the real git, since they serve a repository named by
argument and run nothing of the caller's. `gitguard trust`, `list` and
`retrust` warn while the exec path is not wrapped: gitguard then checks
the repositories you run git in, as before, but not the ones git enters
on its own. To undo:

```sh
sudo rm /usr/bin/git /usr/lib/git-core/git
sudo dpkg-divert --package gitguard --rename --remove /usr/bin/git
sudo dpkg-divert --package gitguard --rename --remove /usr/lib/git-core/git
```

On macOS `/usr/bin/git` is protected by SIP and renaming Homebrew's git is
undone by `brew upgrade`: keep the `PATH` symlink (it covers everything
started from a login shell, VS Code included), set `git.path` in VS Code,
and for the exec path give git a directory of your own: copy or link the
content of `$(git --exec-path)` into `~/.local/lib/git-core`, replace its
`git` by a symlink to gitguard and relink the dashed builtins to it, then
export `GIT_EXEC_PATH=~/.local/lib/git-core` in your shell profile (and
`launchctl setenv GIT_EXEC_PATH …` for GUI apps). Redo it after `brew
upgrade git`; `gitguard trust` tells you when it is stale.

### First trust

Set git's own guard against bare repositories planted in subdirectories; it
works with or without gitguard:

```sh
git config --global safe.bareRepository explicit
```

Then, in each existing repository, **look before you trust**: the whole
point is that no state is blessed unseen, so there is no trust-on-first-use.

```sh
cat .git/config; ls -la .git/hooks     # anything you did not put there?
gitguard trust
```

`gitguard list` shows every registered repository and its status. New
repositories need nothing: a successful `git clone` / `git init` through the
wrapper is trusted automatically (unless a template directory or
`--separate-git-dir` is involved, in which case it says so).

## Day to day

Commit, checkout, merge, rebase, stash, bisect, gc, worktree and submodule
operations touch only volatile files: nothing to do. When a command finds
the repository changed, one of three things happens.

`git --version` is never checked: it reads no repository, and the tools
that run it first (lazygit, fugitive) took a refusal for an old git.

**Auto-accept: the change is one git or your editor made itself.**
gitguard re-trusts on its own, prints one line and runs git. See the next
subsection for the exact rule.

**Anything else is shown and asked on the terminal.** A new remote, a hook,
an `include.path`: the diff is printed, then

```
Trust this state and run git? [y/N]
```

The question is read on `/dev/tty`, so git's own stdin (`git apply <
patch`) is untouched. The state recorded is the one you were shown, not
whatever the sandbox may have written in the meantime. No question, a plain
refusal, when stdout or stderr is not a terminal (a prompt's `$(git …)`,
`git log | head`), or with `GITGUARD_NO_PROMPT=1`.

**A git with no terminal waits for you.** An editor's polling, a build tool,
cron: nobody reads their stderr. On a changed repository that git records
what it saw, sends one desktop notification (`notify-send` on Linux,
`osascript` on macOS, at most one per repository per 10 minutes) and waits
up to `GITGUARD_WAIT` seconds (default 60; 0 = never) for your decision:

```
$ gitguard pending
changed         4s  1 waiting  /home/user/work/api
  gitguard pending <repo>   to see the diff and decide     -a: all
$ gitguard pending ~/work/api
/home/user/work/api  [changed, since 6s]
    git waiting (pid 41250, 6s): code[40988] ← systemd[1]
      /usr/share/code/code --type=utility
────────────────────────────────────────────────────────
  added     hooks/pre-commit
────────────────────────────────────────────────────────
Allow: record this state and let the waiting git run? [y/N] n
! gitguard: refused: the waiting git is not run; the record is cleared. If malicious:  gitguard restore
```

Allowing records the state you were shown and lets the waiting git run.
Refusing makes it fail; `gitguard restore` then puts the watched files back
and you inspect the rest by hand. If the files changed again between the
block and your review, the diff shown is the current one and says so. A
decision taken after the timeout applies to the next invocation (editors
poll again by themselves). A never-trusted repository or a structural
anomaly is recorded and refused at once: nothing can be allowed there
without `gitguard trust` after inspection.

`gitguard trust` on a changed repository shows the same diff and asks the
same way; in a script it prints the diff and records.

### Auto-accept

Not to be confused with **auto-trust**, which blesses a *new* repository
after a `clone` or `init` made through the wrapper. Auto-accept applies to
a repository already trusted that now differs from its reference, and
accepts the difference without asking when it is one of the few things git
and your editor write into `.git/config` by themselves in the course of a
normal day. The point is to keep the `[y/N]` question for the rare changes
you will actually read (`remote add`, a hook, an `include.path`), instead
of training a reflex `y`.

The rule: the only file that changed is `.git/config` (or the main
repository's config, when working from a linked worktree), and the
**semantic** difference between the trusted config and the new one is
limited to added or removed lines of these keys (a config that only differs
by a comment has no semantic difference, and is not accepted either):

| Key | Written by | Accepted value | Why it cannot run anything |
|---|---|---|---|
| `branch.<x>.remote` | `push -u`, `branch -u`, `checkout -b` with `autoSetupMerge` | a remote already present in the trusted config, or `.` | names an existing `[remote]` section; a new remote is not accepted this way |
| `branch.<x>.merge` | same | `refs/heads/…` | a ref name git resolves, never executes |
| `branch.<x>.vscode-merge-base` | VS Code's git extension, when it opens a repository | a ref name: no leading `-`, no blank, no control character | git ignores the key; VS Code passes the value to `git merge-base` |

Anything outside this, a `branch.<x>.rebase` or a new `[remote]` section
for instance, goes through the question. It is a closed allowlist of three harmless keys, not
a blocklist of dangerous ones: nothing enters it without a demonstration
that the key cannot make git execute anything. Since git writes these
lines *after* the check (`push -u` runs, then records the tracking), it is
the next command that accepts them.

Tried on Debian with the system-wide install, on a repository modified
behind the user's back: starship, oh-my-zsh, fish and `__git_ps1` prompts
go quiet with no delay (their git has the terminal: refused at once);
powerlevel10k keeps showing branch and status, since `gitstatusd` reads
`.git` directly and never runs git, which is harmless; lazygit exits with
gitguard's message, tig says "Not a git repository"; fugitive's `:Git`
shows the refusal after `GITGUARD_WAIT` (its first git is a job without a
terminal, which waits); pre-commit's hook runs with the real git, and the
`pre-commit install` that rewrote the hook is what asks for a `trust`.

To try the waiting path by hand, start a git with no controlling terminal.
`nohup` and `&` keep the terminal; `setsid` detaches on Linux, and on macOS,
which has no `setsid`, Python's `start_new_session` does the same:

```sh
cd ~/work/api && printf '#!/bin/sh\necho pwned\n' > .git/hooks/pre-commit
GITGUARD_WAIT=300 python3 -c 'import subprocess, sys
subprocess.run(sys.argv[1:], start_new_session=True, stdin=subprocess.DEVNULL,
               stdout=open("/tmp/git.log", "w"), stderr=subprocess.STDOUT)' git status &
gitguard pending ~/work/api      # decide; then read /tmp/git.log
```

### After upgrading gitguard

A new version may change what the fingerprint contains; `gitguard list`
then shows the repositories as "legacy". `gitguard retrust` re-validates in
bulk the ones that are unchanged and skips the modified ones.

## Commands

| Command | What it does |
|---|---|
| `gitguard` | Check the current repository. Exit 1 if suspect or never trusted. |
| `gitguard trust` | Record the current state as the reference, with a backup of the watched files. Shows the diff first if the repository changed. |
| `gitguard diff` | Show what differs from the reference. |
| `gitguard restore [-y]` | Put the watched files back into the reference state. |
| `gitguard git <args>` | Check, then run the real git. Honours `-C`, `--git-dir`, `--work-tree`, `-c`. |
| `gitguard list` | Registered repositories and their status (ok / modified / structure / missing / legacy / unknown). |
| `gitguard pending [<repo>… \| -a \| -c <repo>…]` | Decisions waiting for a git blocked by a program: list, review and allow/refuse, or clear. |
| `gitguard forget <repo>…` / `--missing` | Remove entries; the repository becomes "never trusted" again. |
| `gitguard prune` | Same as `forget --missing`. |
| `gitguard retrust` | Re-validate unchanged repositories after an upgrade. |

Management commands write to stdout (`gitguard list | grep modified`
works); refusals and diagnostics go to stderr.

## Environment variables

| Variable | Effect |
|---|---|
| `GITGUARD_STATE` | State directory (default `$XDG_STATE_HOME/gitguard`, i.e. `~/.local/state/gitguard`). Never inside a mounted volume. |
| `GITGUARD_REAL_GIT` | Path to the real git (default: a `git.real` next to gitguard, else the first `git` in the PATH that is not gitguard itself). Changing the real git changes its system config, hence the fingerprint: one `trust`. |
| `GITGUARD_ALLOW_REBASE_EXEC=1` | Allow `exec` lines in rebase todo files, and a merge strategy that is not one of git's builtins (`rebase-merge/strategy`, `sequencer/opts`). |
| `GITGUARD_NO_PROMPT=1` | Never ask on the terminal; refuse directly. |
| `GITGUARD_WAIT` | Seconds a git without a terminal waits for `gitguard pending` (default 60, 0 = never). |
| `GITGUARD_NO_NOTIFY=1` | No desktop notification. |
| `GITGUARD_DEBUG=1` | Full traceback on internal errors (otherwise a one-line message, exit 1, git not run). |
| `NO_COLOR` | Disable colours. |

Git's own `GIT_DIR`, `GIT_WORK_TREE`, `GIT_COMMON_DIR`, `GIT_INDEX_FILE`,
`GIT_CEILING_DIRECTORIES` and `GIT_CONFIG_*` are read as git reads them:
the repository checked is the one git opens. A relative `GIT_COMMON_DIR` is
refused (git itself reads it against two different directories in one run).

## What it does not do

- It only covers git invocations that resolve to the wrapper. A tool with a
  hardcoded path to the real git, or started with a `PATH` that does not
  contain the symlink, is not checked (see "You are not the only one running
  git"). A `-c key=value` or a `GIT_INDEX_FILE` given to such a git is
  invisible too.
- It cannot close the race between its check and git's execution if the
  sandbox is still writing. Stop the sandbox before running git on the host.
- `restore` only cleans the pivot vector: objects, commits and tree files
  dropped by the sandbox stay there for you to inspect. It never writes
  outside the repository: a watched file there (`../shared-hooks`) is named
  and left for you.
- Hooks tracked *in the tree* under `core.hooksPath` (husky, `.githooks`)
  are watched, but a `checkout`/`merge`/`pull` of a commit the sandbox
  created rewrites them after the check, and git runs the new version in
  the same command. `gitguard trust` warns when that layout is in place;
  review incoming changes to those files.
- The `[y/N]` question needs stdout and stderr on a terminal. A shell
  prompt's `$(git …)` or a `git log | head` on a changed repository is
  refused, not asked: rerun without the pipe, or `gitguard trust`.
- No desktop notification without a session (ssh, cron, systemd): the
  pending record is still written and the wait still times out; check
  `gitguard pending` by hand.
- Your global config is read for the paths it names, not fingerprinted: a
  `git config --global` that names no file (an alias, a pager) is not seen.
  Whoever could write it could write gitguard's state directory too.
- Bare repositories are refused, not managed. `core.splitIndex` is refused
  (the gitlinks it needs to read live in `sharedindex.*`).
- Parity with git is checked against git itself in `tests/test_git_parity.py`;
  a gap found there is marked as an expected failure until fixed (none open
  at the moment). Deliberate, fail-closed divergences: a NUL byte or a line
  git dies on in a config file is refused.

`DESIGN.md` holds the design notes, the review method and the catalogue of
the 99 bypasses and false positives found so far (`tests/attacks/`).

## Tests

```sh
python3 -m pytest
```

Needs `pytest` and `git`. The suite replays a corpus of attacks against a
trusted repository and checks that each one is refused, that ordinary git
operations are not, and that everything git reads (config syntax, includes,
discovery, index gitlinks) gitguard reads the same way, with git as the
oracle.

## License

MIT — see `LICENSE`.
