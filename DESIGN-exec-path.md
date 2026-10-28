# gitguard at git's exec path — design draft

Branch `exec-path-wrap`, 2026-10-26. A working document: it will be reworked
here and merged into DESIGN.md once the implementation has settled. Steps 1
to 3 and 5 of the plan (section 8) are implemented on the branch and green
on macOS (git 2.50) and on the Debian VM with the system-wide diversion
(git 2.47.3); step 4's `.deb` is not written, the manual diversion is.
Correction found while testing, section 6: `ls-files` and `grep` with
`--recurse-submodules` do run the nested repository's config in-process.

## 1. The problem this solves

Every git enters another repository through a **child process**. `git
status` asks each submodule `git status --porcelain=2`; `diff.submodule =
diff` runs `git diff` inside it; `submodule--helper` has 24 spawn sites;
`merge`, `commit`, `fetch`, `rebase`, `am` and `revert` end with `git
maintenance run --auto`; `pull` is `fetch` then `merge`. The child is not
the `git` of the user's PATH: `setup_path()` (`exec-cmd.c`) puts the
**exec path** first in the child's PATH and exports `GIT_EXEC_PATH`, so the
child is `<exec-path>/git` — `/usr/lib/git-core/git` on Debian,
`/opt/homebrew/libexec/git-core/git` with Homebrew — the real binary. A
`git → gitguard` symlink ahead of the PATH wraps the first process of a
command and none of its children. DESIGN.md says it in one line ("only
covers invocations that go through the wrapper"); the line hides a family.

gitguard has emulated the child's judgment from the parent: a gitlink
barrier in the index ([14]), then a `-c diff.ignoreSubmodules=dirty` switch
when a command brings a gitlink ([66]), then the list of commands that
bring one ([77]), then autocorrect ([78]), then the inversion to a closed
exemption ([86]), and still [89] (`--submodule=diff`) open, [95]
(`maintenance` reading an include the command just checked out) open.
Each step guessed the routes by which git enters; each review found one
more. Thirteen catalogue entries are this family: [6] [7] [14] [24] [36]
[60] [66] [77] [78] [86] [87] [89] [95].

**Experiment (Debian 13 VM, git 1:2.47.3, 2026-10-26).** `/usr/bin/git` was
already a `dpkg-divert` to `git.real`; `/usr/lib/git-core/git` was not.
Diverting it too, with gitguard handling the `git-<cmd>` name: the suite
gave 1040 passed, 210 failed, and **six strict XPASS — [89] ×5 and [95]**,
the only xfails of this family. The positive controls of [66] fail in the
right direction: the real git can no longer enter the planted repository.
The 210 failures are three classes, all design (section 6), none a flaw of
the idea. Per-child cost on a trusted repository, same gitguard as parent
and child: `log -1` 26 ms (no child), `commit` 26 → 50 ms (one child), an
alias with three children 27 → 101 ms. About 25 ms per child on the VM,
the Python floor plus the check; ~35 ms expected on macOS.

## 2. The model

> A repository is judged once per user command, by the first gitguard that
> opens it. Every other repository git enters during that command is judged
> at entry, by the gitguard that is its first process there. What a command
> writes into a judged repository is judged at the next command.

The first sentence is today's gitguard. The second replaces the guessing:
there is no longer a question "will this command enter a submodule?" —
whatever enters, enters through gitguard. The third sentence is the
boundary kept on purpose: [44] (a tracked hook checked out, then run) and
[95] (a tracked include checked out, then read by the `maintenance` child)
are the same repository, the same command; they stay accepted limitations
(section 5).

What it replaces, to be removed once the install is verified (section
3.8): `with_ignored_submodule_dirt`, `SWITCH_EXEMPT`, `exempt_from_switch`,
the alias reading done for the switch in `_alias_parts`/`_shell_alias_words`
(the alias reading for the `-c` pairs, [80], stays), `EXEMPT_FORMS` and the
exemption tests in `test_claims.py`. What stays, unchanged: discovery,
`ConfigScan`, the fingerprint, the structural refusals — `check_nested_git`
included: a gitlink in the index naming a repository whose gitdir is not
under `modules/` is still refused by the parent, with the message and the
way out, before any child has to refuse it.

## 3. Mechanisms

### 3.1 Invocation names

`main` switches to exec mode on three shapes of `argv[0]`: `git` (today),
a `TRANSPORT` name (today: `git-receive-pack`, `git-upload-pack`,
`git-upload-archive`, passed to the real git without a check), and any
`git-<cmd>` (new: the exec path's 160 dashed builtins are symlinks to `git`
in the same directory, Debian and Homebrew alike; `git-status --short`
becomes `status --short`). A shebang script sees in `sys.argv[0]` the path
the kernel execed, so the basename is the name git used.

`real_git()` already prefers a `git.real` next to the invoked path: with
the divert layout that is `/usr/lib/git-core/git.real` for a child and
`/usr/bin/git.real` for the user's command. No recursion: the real git's
exec path is compiled in (Debian builds without `RUNTIME_PREFIX`, checked:
the binary copied elsewhere still answers `/usr/lib/git-core`), so the
real git finds its helpers, and its `git` children resolve to gitguard.

### 3.2 The judgment marker

When gitguard has judged a repository and runs the real git, it puts in
that process's environment:

```
GITGUARD_JUDGED=<pid>.<start>:repo=<gitdir>,<common dir>,<root>,<label>
```

the paths resolved and hex-encoded (a path holds anything but NUL, the
one byte an environment value cannot; `label` is the directory the state
key is named after, for a child that must read the parent's manifest),
`pid` and `start` the process that set it and its start time: gitguard
itself, which execs the real git under its own pid, or stays the parent of
a clone it waits for.

Not signed, on purpose. The marker could only be forged by whoever sets
the environment of the user's git: the user's shell, a `direnv allow`, a
trusted hook or alias. The sandbox writes into the volume, never into a
host process's environment, and no config value it controls becomes one
(everything that runs is in the fingerprint; a planted repository's config
is never read by the real git, gitguard refuses first). That class —
`PATH`, `GIT_DIR`, `GIT_CONFIG_GLOBAL` set by an attacker — is out of the
model already ("Known limitations"); every other variable gitguard reads
(`GITGUARD_REAL_GIT`, `GITGUARD_STATE`, git's own) is trusted the same way,
and a signed marker would be the one exception, a secret to store, prune
and permission for no threat in the model.

The marker **lives as long as the process that set it**: a child accepts
it only while that process — pid and start time — is one of its
ancestors (`_ancestors`: fields 4 and 22 of `/proc/<pid>/stat` on Linux,
`pbi_ppid` and `pbi_start` of `proc_pidinfo` on macOS; a chain that cannot
be read stops there, fail closed; the reading process is not its own
ancestor). That is the lifetime of the command, however long — a `clone
--recurse-submodules` of a large tree, a `filter-branch`, a `bisect run`
— and not a moment more: an environment variable that outlived its git (a
detached shell, an editor's daemon) names a process that is no ancestor.
The pid alone was not enough ([114]): a process holding an old marker long
enough (an Emacs daemon started from the editor of `git commit`, `code
--wait`, a tmux server) saw the counter wrap and one of its own children
get the marker's pid; the start time tells them apart. A marker whose
process is gone is **no marker**: the user's semantics. A child git does
not leave the tree either: `maintenance run --detach` (what git ≥ 2.47
passes to the auto-maintenance after a command) and `gc --auto` under
`gc.autoDetach` daemonize, and their gc, repack, prune found the marker
dead — in a submodule, refused at every fetch ([117]). `keep_attached`
turns them into `--no-detach`: the auto-gc runs before the command
returns. The
first design expired the marker by the clock instead (a TTL of 60 s,
[104]); the 15th adversarial pass showed the clock changing the *answer*
mid-command, not only its cost — every submodule of a clone longer than a
minute refused as never trusted, a `rebase --exec` stopped half-way — and
a stale marker in an editor's shell keeping child semantics for ever.

A gitguard child reads the marker before anything else. It applies the
global options (`-C`, `--git-dir`: they decide which repository), finds the
root, opens the repository and:

- **covered** (3.3) → **inherits**: no fingerprint, no structural check, no
  prompt; straight to the real git, marker passed on unchanged (a
  grandchild in the same repository inherits too).
- otherwise → the **full check**, as if it were the user's command, then
  its own marker for its children.

Inheritance skips the judgment of **the repository**, not the checks on
**the child's own arguments**: a covered `push` or `archive --remote`
child is judged on where it goes and on that alone (`check_remote_destination`,
[62] [70] [108]: a hook or alias of the trusted config may legitimately
run `git push`, and a submodule's push must not be judged under the
submodule's own key); `parse_new_repo` sets the `new` marker (3.4).

### 3.3 Covered by the judged repository

A child's repository is covered when its **resolved gitdir and common dir
are both gitdir roots the parent's walk descended**: the judged gitdir,
the judged common dir, and every root nested under their `modules/` and
`worktrees/` (`gitdir_roots`, the same recognition as the walk's
`_child_root`: a `HEAD` or a `commondir` under those two directories, and
nowhere else). Covered means hashed: the content of those roots is in the
judged manifest, so the judgment extends to them. `covers` recomputes
`gitdir_roots` from the file system at the child, not from the parent's
manifest: the difference is exactly the roots the command itself just
created (`modules/<x>` during a `submodule add`), which the rule "what a
command writes into a judged repository is judged at the next command"
(section 2) covers, consistent with [107]. This is what makes a
real submodule's `git status --porcelain=2` pass without a `trust` of its
own, lets `git worktree add` run its `git reset --hard` in the new
worktree, and covers a worktree's own submodules
(`worktrees/<wt>/modules/<x>`), a `--separate-git-dir` repository's, a
submodule's submodule worked in directly ([102]: the first rule, the
name `.git` and a prefix under it, covered none of those and every
`status` there was refused).

The rule is on what was hashed, not on where a path sits: a gitdir
planted in a **volatile zone** of a real submodule's gitdir
(`.git/modules/sub/refs/p`, where nobody hashes), named by a gitlink in a
commit the sandbox writes, is under `modules/` and covered by nothing —
the child judges it on its own and refuses it ([103]; by the submodule's
index the same planting is caught one step earlier, `check_nested_git`
requiring a gitdir root, which it did not before). A gitfile pointing
outside the roots ([7] [24]) gets its own key and is never trusted.

A child at **another work tree root** — a submodule, a linked worktree,
the same gitdir with `--work-tree=<site>` or `filter-branch`'s
`.git-rewrite/t` — has its gitdir hashed, not its tree: what its config
names there (a relative `core.hooksPath`, an include, a script:
`tree_named`, every `wt` reference but the tree's own structure,
`.gitmodules` and gitfiles) resolves under a root the parent did not walk
([72]). Covered when every one of those paths was hashed by the parent (a
submodule's hooks: the parent's scan resolves each submodule's config
against its tree, [39]) or holds the same content at the same place in the
judged tree (a linked worktree of a branch with the trusted hooks);
otherwise judged on its own key. The rule replaces two that each failed
one way: "the same gitdir must have the same root" refused every
`filter-branch` ([115]), and "any other root is fine" let `worktree
remove` run a hook the sandbox wrote in the linked worktree ([120]). A
trusted alias `!git --work-tree=<site> checkout -f main` with a relative
hooksPath is still judged at `<site>` ([111]). Linked worktrees keep their
own trust key for the **user's** commands, as before.

### 3.4 Two more marker values

- `GITGUARD_JUDGED=<pid>.<start>:new=<path>[,<gitdir>]` — set by `run_git` for
  `clone` and `init` (the parent judges nothing: the repository does not
  exist yet; auto-trust comes after git returns). Covered: anything whose
  gitdir, common dir **or** root is `<path>` or under it, or at `<gitdir>`
  (`--separate-git-dir`). The clone's own `index-pack` runs with
  `GIT_DIR=<new>/.git` from the user's cwd ([101]: compared by root alone,
  every clone but of a plain local path died "never trusted" — and from a
  trusted cwd reported a false diff of it); the submodule clones of
  `--recurse-submodules` run under `<path>`. Every form of clone and init
  sets it, bare and template included (`NewRepo`); only the auto-trust
  is withheld for those.
- A **served repository**: `git-receive-pack`, `git-upload-pack`,
  `git-upload-archive` (`TRANSPORT`, the dashed names sshd runs) and the
  same as a first word (`SERVERS`: what `git daemon`, `http-backend` and
  `git-shell` run, [106]) serve the repository named by their argument, a
  bare one gitguard does not handle, and run nothing of the cwd's. The
  passthrough sets an ordinary `repo` marker for that repository, opened
  as enter_repo opens it (`_local_remote`), with an empty root and label:
  nobody judged it as a whole. Its children (`index-pack`, `pack-objects`,
  `update-server-info`, `maintenance`, the hooks' gits in that repository,
  `upload-archive--writer <dir>` [118]) inherit when they are in that
  gitdir and common dir **exactly** — not its `worktrees/*` or `modules/*`,
  which nobody walked ([121]) — and in a tree where its config names
  nothing: push-to-deploy's `update-index` in a non-bare remote whose
  relative hooksPath names its tree is judged under the remote's own key
  ([122]). A hook that enters **another** repository (`cd site && git
  pull`) judges `site` ([105]; the first value, `serving`, covered
  everything). Without a
  marker every ssh push *to* the machine fails at `index-pack` — the
  incident that created `TRANSPORT` on the VM, one level down.

### 3.5 What a child never does

A child shares the parent's session and terminal. The exec-mode behaviour
of a refusal (a `[y/N]` on `/dev/tty`, or without a terminal a `pending`
record and a wait of `GITGUARD_WAIT` seconds) is wrong there: the parent
git may be reading stdin or holding the pager, and a `git status` meeting
a planted repository would hang a minute. With a live marker present,
whatever its value:

- a refusal is **immediate**: no question, no wait; the `pending` record
  is written (the user sees it with `gitguard pending`), the desktop
  notification is not sent (the parent's stderr carries the message);
- nothing is written to **stdout** (git parses the child's stdout:
  `status --porcelain=2`, `rev-parse`); exec mode already keeps its
  messages on stderr, the rule becomes a test;
- **no auto-accept** of a branch-tracking change: a child writes no trust
  state for a repository it judged.

A child's **clone or init is the user's**: waited for, `new` marker set,
auto-trusted ([107]: pre-commit's first-use `git init` in its cache, a
hook's clone) — unless the marker already covers the result (`submodule
add`'s clone into `modules/<x>`, the submodules of `clone
--recurse-submodules`), which the parent's next command, or the clone's
own auto-trust, takes as a whole; the new repository is opened at its
path, not through the `GIT_DIR` git exports to that child.

The parent git sees the refused child fail: `git checkout` prints "Could
not run 'git status --porcelain=2' in submodule vendor/x" after gitguard's
own "repository never trusted: …/vendor/x" on stderr, and exits non-zero.
`commit` ignores its `maintenance` child's failure, as git documents.

### 3.6 Passthroughs that read no repository

`git --exec-path` (no `=`), `--html-path`, `--man-path`, `--info-path`:
`handle_options` in `git.c` prints and `exit(0)`s before any setup. The
shell scripts of the exec path (`git-submodule`, `git-mergetool`,
`git-request-pull`, `git-filter-branch`…) start with `.
"$(git --exec-path)/git-sh-setup"`: with a check in the way (a never-trusted
repository) the output was empty and `git-submodule` died on "cannot open
/git-sh-i18n". They join `passthrough` with `--version`, with a claims
test holding the list to `git.c` (the inventory's [options] section names
them).

### 3.7 Verifying the wrap

The switch and the exemption are removed; a machine whose exec path is not
wrapped would then be *less* protected than today ([66] open). So the wrap
is a precondition gitguard checks, at `trust`, `retrust` and `list` (where
`check_safe_bare` already warns): `<exec-path>/git` must resolve to
gitguard itself, the exec path being `GIT_EXEC_PATH` if set, else what the
real git answers to `--exec-path`. That is one run of the real git without
a repository, the same class as `git --version` (no `RUN_SETUP`), and the
only git gitguard ever runs. Not on every command: a warning repeated a
hundred times is ignored. Whether an unwrapped exec path is a warning or a
refusal to `trust` is open (section 9).

### 3.8 Order of the changes

1. The marker (3.2), the coverage rule (3.3), `new` and the served repository (3.4),
   the child behaviour (3.5), the passthroughs (3.6), the `git-<cmd>` name
   (3.1): gitguard works both wrapped and unwrapped.
2. The verification (3.7) and the Debian install (section 4).
3. The tests (section 7) on the wrapped VM.
4. Only then, the removal of the switch and the exemption, and the
   rewriting of "Nested repositories" in DESIGN.md.

## 4. Installation

### 4.1 Debian: `dpkg-divert`

The mechanism Debian provides for one package to replace a file of
another: dpkg records the diversion and, on every upgrade of `git`,
installs the new binary at the diverted name, never over gitguard.
`/usr/bin/git` is already diverted this way on the VM (`--package
gitguard`, since 2026-10-19). The exec path needs the same:

```sh
dpkg-divert --package gitguard --add --rename \
    --divert /usr/lib/git-core/git.real /usr/lib/git-core/git
ln -s /usr/bin/gitguard /usr/lib/git-core/git
```

Facts that make this one file enough (checked on git 1:2.47.3-0+deb13u1):
all 160 dashed builtins of `/usr/lib/git-core` are symlinks to `git` in
that directory; `/usr/bin/git-receive-pack` and `git-upload-pack` are
symlinks to `/usr/bin/git`; the real git keeps its compiled exec path
wherever its file sits; `/usr/bin/git` and `/usr/lib/git-core/git` are two
separate files in the package (not a hard-link pair), so each diversion is
independent. The non-git programs of the directory (`git-remote-https`,
`git-http-backend`, `git-daemon`, the shell and perl scripts) are untouched
and keep working: they call `git`, which is gitguard.

The proper form is a `gitguard` package: `Depends: git, python3`; `preinst`
adds the two diversions (`--package gitguard`, so `apt upgrade git` and
`apt remove gitguard` never fight), the package ships `/usr/bin/gitguard`
and the two symlinks as its own files, `postrm remove` removes the
diversions with `--rename` — `apt remove gitguard` restores the original
git byte for byte. The example in `dpkg-divert(1)` is this shape.

Verification from any directory:

```sh
git -c alias.w='!readlink -f $(which git)' w     # /usr/bin/gitguard
```

### 4.2 macOS, or no root: a shim exec path

Homebrew has no diversion; `brew upgrade git` replaces the Cellar. The
only clean handle is `GIT_EXEC_PATH`, which git honours before its
compiled path: a directory `~/.local/lib/gitguard-exec/` holding `git →
gitguard`, `git.real → <Cellar>/libexec/git-core/git`, and a symlink for
every other entry of that directory, built and rebuilt by `gitguard
exec-path [<dir>]` (it links the entries by Homebrew's stable
`opt/git/libexec/git-core` path, so an upgrade breaks only what it adds
or removes); `GIT_EXEC_PATH` set for the session (`launchctl setenv` for
GUI apps, the shell profile for terminals). `git.real` is not optional: a
GUI app's PATH holds only Apple's git, which became the real one without
it ([119]). The trust-time verification (3.7) says when it is stale:
entries of the real exec path missing, or links to nothing. Weaker than Debian:
a process that does not inherit the variable has unwrapped children, i.e.
today's protection. The same shim is the test tool for experiments without
root (it is how the per-child numbers above were measured), and the
per-user install on Linux (README, "Per user"); `_core_exec_path` takes
`git.real` of the real exec path when the diversion left one, whatever
gitguard that path's `git` is.

### 4.3 The VM

`/usr/bin/gitguard` on the VM is the version of 2026-10-19: it still hashed
the global config ([56] was fixed after). Mixing it with the current
script gives false "changed: added global:…" refusals. Update it before any
system-wide replay; keep the `git.real` layout.

## 5. What it closes, what it does not

| | entries | after |
|---|---|---|
| git enters another repository through a child | [6] [7] [14] [24] [36] [60] [66] [77] [78] [86] [87] | covered twice: the parent's structural refusals, the child's refusal at entry |
| the submodule content diff | [89] | **closed** (XPASS on the VM); the accepted-limitation text and the `trust` warning go |
| a tracked include read by the `maintenance` child | [95] [123] | **stays**: same repository, same command (section 2). Joins [44] as an accepted limitation; `trust` names every file the config names in the tree. A re-check by the child was tried and reverted ([124]) |
| an active submodule entered in-process (`submodule.active` pathspec, `grep --recurse-submodules <tree>`) | [126] | **accepted limitation**: by-name activation stays hashed and refused; `trust` warns on a pathspec, with the way out |
| tracked hooks, sh readings | [44] [71] [74] | unchanged |
| everything else (fingerprint scope, parsers, discovery, options, remotes, FPs) | ~75 | unchanged, untouched |

New coverage with no catalogue number yet: a trusted hook or alias that
runs `git` in another repository; a tool that calls the exec path's `git`
directly; `git submodule foreach` with any command.

Removed with the switch: the user-visible cost it had — `git status`
reports dirty submodules again (`test_exempt_commands_still_report_a_dirty_submodule`
documented the loss).

## 6. Risks and costs

- **The barrier becomes a claim about git.** Today gitguard guesses the
  *routes*; tomorrow it assumes git enters a repository *through a
  process*. Better, still a claim, and git's trend runs against it:
  `ls-files --recurse-submodules`, `grep --recurse-submodules` and `diff
  --submodule=log` already read the child repository **in-process**
  (`repo_submodule_init`). Measured (git 2.50 and 2.47.3): `ls-files` and
  `grep` **do run** the nested repository's `core.fsmonitor` in-process
  (its index is refreshed); `diff --submodule=log` and `rev-list --objects`
  do not. What stands in the way is two barriers, not one: an in-process
  entry needs an *active* submodule, and activation **by name** takes
  `submodule.<name>.url` or `.active` in `.git/config`
  (is_submodule_active reads the config, not `.gitmodules`), which is
  hashed; the readers that take the gitlink from the index meet the
  structural refusal first. Neither bars a **pathspec** activation already
  trusted — `submodule.active = .`, what `clone --recurse-submodules`
  writes — met by a gitlink in a tree object: `grep --recurse-submodules
  <tree>` then opens the planted gitdir in-process ([126], accepted
  limitation; `trust` warns on the pathspec and names the way out). The
  day `status` goes in-process,
  the barrier vanishes without a test going red — unless the test exists.
  Hence (section 7, implemented): a claims test "git enters a planted
  repository through a child process" with a positive control, and a table
  of the in-process entries with, for each, whether it runs the nested
  config and what bars the activation. Replayed at each git release,
  like `tests/inventory/`.
- **Cost per child**: 25 ms on the VM, ~35 ms on macOS, inheritance
  included (the Python floor dominates). `pull` ≈ +3 children, `status`
  with N submodules +N, `filter-branch` and `bisect run` hundreds. Accepted
  for the transition; a Rust port removes it (floor ~2 ms).
- **Fail-closed failure modes** to keep in mind: a transport passthrough
  without its marker breaks every ssh push to the host; a stale macOS
  shim after `brew upgrade` breaks every child ("no git"); a mixed install (old script in
  `/usr/bin`, new at the exec path) refuses everything as changed. The
  trust-time verification (3.7) reports the first two.
- **The marker's residual window**: a shell opened from a git-spawned
  editor inherits the marker for as long as that git lives: a `git` typed
  there in the judged repository skips its check, one typed in another
  repository refuses without asking (recorded for `gitguard pending`). One
  repository, a process the user started by hand: documented, not closed.
- **IDE polling**: an IDE running `git status` every few seconds in a
  repository with a planted nested repository produces one refused child
  per poll; `update_pending` dedups by key, the notification is not sent by
  children, stderr goes to the IDE's log. Same volume as today's parent
  refusals.
- **Partial commands**: a child refused mid-command leaves git's own state
  as git left it (a `checkout` whose submodule summary failed has already
  moved HEAD and the index). The next user command is refused
  structurally ([14]); nothing ran.

## 7. Tests

- `conftest`: two exec paths. The scenarios are built with the real git
  **and raw children** (`GIT_EXEC_PATH` = a raw copy: `git → git.real`,
  the rest symlinked), the checks run with the **wrapped** exec path (`git
  → gitguard.py`). On a machine where the exec path is already wrapped,
  the raw directory is built from `git.real`.
- `test_claims.py`: every passthrough of 3.6 prints and exits with no
  repository (oracle: `git.c`, the inventory's [options]); git enters a
  submodule through a child (positive control: wrapped exec path, planted
  repository, child refused, payload not run; and the unwrapped control,
  payload run); the in-process entries run nothing of the child's config
  (one parametrised test per `repo_submodule_init` command); the marker is
  rejected when expired or for another key, and never read from a
  repository (environment only).
- `test_commands.py`: the positive controls of [66] [77] [86] [89] invert
  (the real git with wrapped children does not run the payload; with raw
  children it does); `clone --recurse-submodules`, `submodule add`,
  `submodule update --init`, `worktree add`, `push -u`, a push to a local
  bare remote, an ssh-shaped `git-receive-pack` with children: all
  complete; a child never prompts (pty test: the parent holds the tty, the
  child refuses at once) and never waits.
- `test_legit.py`: `status` with ten submodules, `submodule foreach`,
  `filter-branch` on a small history: silent, and their timings recorded
  in PERF.md (new table: per-child overhead).
- The attack corpus: unchanged in content; `test_attacks.py` runs each
  attack under both exec paths.
- VM replay of the whole suite with the system-wide divert, after the
  `/usr/bin/gitguard` update (4.3).

## 8. Work plan

| step | content | size |
|---|---|---|
| 1 | marker (3.2); coverage rule (3.3); `new`/served (3.4); child behaviour (3.5); passthroughs (3.6); `git-<cmd>` (3.1) — redone after the 15th pass ([101]–[112]): pid lifetime, coverage by `gitdir_roots` | 2 days |
| 2 | conftest two exec paths; claims tests of section 7 | 1 day |
| 3 | positive controls inverted, legit scenarios, pty test for children, PERF.md | 1 day |
| 4 | verification at trust (3.7); Debian install script and `.deb` skeleton; VM update and replay | ½–1 day |
| 5 | removal of the switch, `SWITCH_EXEMPT`, `exempt_from_switch`, `EXEMPT_FORMS`; DESIGN.md "Nested repositories" rewritten; [89] moved from accepted to fixed, [95] warning on includes in the tree; catalogue entry for this design | ½ day |

Step 1 alone leaves gitguard working on an unwrapped machine exactly as
today; the removal in step 5 is the only step that requires the install.

## 9. Open questions

1. *Decided 2026-10-27*: unwrapped exec path at `trust` is a warning
   (`check_wrap`), no refusal, no switch standing in: the wrap is the
   install, a fallback that is sometimes on would make the protection
   depend on an install detail nobody sees, and refusing `trust` would
   break macOS while the wrap there is fragile.
2. *Decided 2026-10-27*: no TTL. The marker lives with the process that
   set it (3.2, [104]).
3. *Decided 2026-10-27*: worktree children inherit the main repository's
   judgment for their gitdir, and for their tree only what the parent
   hashed (3.3, [120]); no third auto-trust path.
4. *Decided*: the `-c diff.ignoreSubmodules=dirty` switch is removed (see 1).
5. The Rust port: not a condition of this design, but the per-child floor
   is its first concrete justification. Not before the design has settled
   on this branch.
