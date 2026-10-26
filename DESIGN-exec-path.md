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

When gitguard has judged a repository of key `K` (section "Storage":
`sha256(resolved root)[:16]`) and runs the real git, it puts in that
process's environment:

```
GITGUARD_JUDGED=<epoch seconds>:key=<K>
```

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

The marker **expires**: a child accepts it only within
`GITGUARD_JUDGED_TTL` seconds (default 60). Not against an attacker: an
environment variable reaches every descendant, not only git's children —
the editor of `git commit`, a shell opened from it (`:terminal`), the
browser of `git instaweb`. Without expiry, every `git` typed in that shell
would skip the check of `K` for the whole editing session. With expiry, a
late child re-checks: today's cost, today's semantics.

A gitguard child reads the marker before anything else. It applies the
global options (`-C`, `--git-dir`: they decide which repository), finds the
root, computes the key, and:

- key equal to the marker's `K`, marker valid → **inherits**: no
  fingerprint, no structural check, no prompt; straight to the real git,
  marker passed on unchanged (a grandchild in the same repository inherits
  too; the expiry bounds the chain).
- otherwise → the **full check**, as if it were the user's command, then
  its own marker for its children.

Inheritance skips the judgment of **the repository**, not the checks on
**the child's own arguments**: `check_remote_destination` ([62], a `git
push <path>` to a repository no trusted config names), `archive
--remote` ([70] [81]), `parse_new_repo` for the `new` marker (3.4). They
are cheap, they are about this argv, and a hook or alias of the trusted
config may legitimately run `git push`, which must be judged on where it
pushes.

### 3.3 Covered by the judged repository

A child's repository counts as `K` when its **resolved gitdir and its
common dir are both under `<K's gitdir>/modules/` or
`<K's gitdir>/worktrees/`**. The content of those directories is in `K`'s
manifest (the gitdir walk descends into them, anchored by `_child_root`),
so `K`'s judgment covers them. This is what makes a real submodule's
`git status --porcelain=2` pass without a `trust` of its own, and what
lets `git worktree add` run its `git reset --hard` in the new worktree.

Anchoring, as everywhere: the rule is on the resolved paths, not on the
gitfile's text. A planted `vendor/x/.git` whose gitfile says `gitdir:
../../.git/modules/x` with a planted gitdir there is caught one step
earlier: `.git/modules/x` is inside `K`'s gitdir, hence in the fingerprint,
hence seen by the parent's check. A gitfile pointing outside `modules/`
([7] [24]) gets its own key and is never trusted.

Linked worktrees keep their own trust key for the **user's** commands
([72]: another tree, other tree-side references); a **child** running in a
worktree of `K` inherits `K`'s judgment. Known gap, accepted because it is
today's state (that child is unwrapped today): a relative
`core.hooksPath` of the common config names `<wt>/.githooks`, which is not
in `K`'s manifest; a child spawned in the worktree by a command of the main
repository would run a hook the sandbox rewrote there. Such spawns are
rare (`worktree add`, `worktree remove`); the user's next command in the
worktree judges it under its own key.

### 3.4 Two more marker values

- `GITGUARD_JUDGED=<epoch>:new=<path>` — set by `run_git` for
  `clone` and `init` (the parent judges nothing: the repository does not
  exist yet; auto-trust comes after git returns). A child whose root is
  `<path>` or under it passes. Without it, `clone --recurse-submodules`
  dies in its first submodule clone ("never trusted"), and the auto-trust
  never happens.
- `GITGUARD_JUDGED=<epoch>:serving` — set by the `TRANSPORT`
  passthrough. `git-receive-pack` and `git-upload-pack` run in a bare
  repository gitguard does not handle; their children (`index-pack`,
  `unpack-objects`, `pack-objects`, `update-server-info`, `maintenance`)
  run there too. Without this value, every ssh push *to* the machine fails
  at `index-pack` — the incident that created `TRANSPORT` on the VM, one
  level down. Not a new exposure: those children are unwrapped today, and
  the served repository is named by sshd's or the pushing git's argument,
  never the caller's cwd.

### 3.5 What a child never does

A child shares the parent's session and terminal. The exec-mode behaviour
of a refusal (a `[y/N]` on `/dev/tty`, or without a terminal a `pending`
record and a wait of `GITGUARD_WAIT` seconds) is wrong there: the parent
git may be reading stdin or holding the pager, and a `git status` meeting
a planted repository would hang a minute. With a marker present, whatever
its value:

- a refusal is **immediate**: no question, no wait; the `pending` record
  is written (the user sees it with `gitguard pending`), the desktop
  notification is not sent (the parent's stderr carries the message);
- nothing is written to **stdout** (git parses the child's stdout:
  `status --porcelain=2`, `rev-parse`); exec mode already keeps its
  messages on stderr, the rule becomes a test;
- **no auto-trust**: a `clone` child of `submodule add` must not register
  `.git/modules/x` as an independent repository in the state; the parent's
  next command sees the new `modules/x` in its own fingerprint and asks.

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

1. The marker (3.2), the coverage rule (3.3), `new` and `serving` (3.4),
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

### 4.2 macOS: a shim exec path

Homebrew has no diversion; `brew upgrade git` replaces the Cellar. The
only clean handle is `GIT_EXEC_PATH`, which git honours before its
compiled path: a directory `~/.local/lib/gitguard-exec/` holding `git →
gitguard`, `git.real → <Cellar>/libexec/git-core/git`, and a symlink for
every other entry of that directory, regenerated by `gitguard
exec-path --refresh` after an upgrade; `GIT_EXEC_PATH` set for the session
(`launchctl setenv` for GUI apps, the shell profile for terminals). The
trust-time verification (3.7) says when it is stale. Weaker than Debian:
a process that does not inherit the variable has unwrapped children, i.e.
today's protection. The same shim is the test tool for experiments without
root (it is how the per-child numbers above were measured).

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
| a tracked include read by the `maintenance` child | [95] | **stays**: same repository, same command (section 2). Joins [44] as an accepted limitation; `trust` warns when an `include.path` resolves inside the work tree, as it warns for hooks in the tree |
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
  do not. What keeps this out of the catalogue: an in-process entry only
  happens for an *active* submodule, which takes `submodule.<name>.url` or
  `.active` in `.git/config` (is_submodule_active reads the config, not
  `.gitmodules`), and `.git/config` is hashed — the sandbox cannot activate
  a planted repository without a refusal. The day `status` goes in-process,
  the barrier vanishes without a test going red — unless the test exists.
  Hence (section 7, implemented): a claims test "git enters a planted
  repository through a child process" with a positive control, and a table
  of the in-process entries with, for each, whether it runs the nested
  config and the refusal of the activation. Replayed at each git release,
  like `tests/inventory/`.
- **Cost per child**: 25 ms on the VM, ~35 ms on macOS, inheritance
  included (the Python floor dominates). `pull` ≈ +3 children, `status`
  with N submodules +N, `filter-branch` and `bisect run` hundreds. Accepted
  for the transition; a Rust port removes it (floor ~2 ms).
- **Fail-closed failure modes** to keep in mind: an unwrapped `serving`
  marker breaks every ssh push to the host; a stale macOS shim after `brew
  upgrade` breaks every child ("no git"); a mixed install (old script in
  `/usr/bin`, new at the exec path) refuses everything as changed. The
  trust-time verification (3.7) reports the first two.
- **The marker's residual window**: within its TTL, a shell opened from a
  git-spawned editor skips the check of that one repository. A minute, one
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
| 1 | marker (3.2) with TTL; coverage rule (3.3); `new`/`serving` (3.4); child behaviour (3.5); passthroughs (3.6); `git-<cmd>` (3.1) | 1 day |
| 2 | conftest two exec paths; claims tests of section 7 | 1 day |
| 3 | positive controls inverted, legit scenarios, pty test for children, PERF.md | 1 day |
| 4 | verification at trust (3.7); Debian install script and `.deb` skeleton; VM update and replay | ½–1 day |
| 5 | removal of the switch, `SWITCH_EXEMPT`, `exempt_from_switch`, `EXEMPT_FORMS`; DESIGN.md "Nested repositories" rewritten; [89] moved from accepted to fixed, [95] warning on includes in the tree; catalogue entry for this design | ½ day |

Step 1 alone leaves gitguard working on an unwrapped machine exactly as
today; the removal in step 5 is the only step that requires the install.

## 9. Open questions

1. Unwrapped exec path at `trust`: a warning (today's protection level,
   silently weaker once the switch is gone) or a refusal to `trust` until
   the install is complete? Leaning: refusal with the install command in
   the message, overridable by `GITGUARD_ALLOW_UNWRAPPED=1` for the macOS
   shim case.
2. `GITGUARD_JUDGED_TTL` default: 60 s covers `submodule update` on a
   normal tree; a `filter-branch` or `bisect run` outlives it and pays a
   re-check per child after the first minute (semantics unchanged). Keep
   60, document, measure.
3. Worktree children (3.3): inherit the main repository's judgment
   (proposed) or carry their own key and make `worktree add` auto-trust
   the new worktree as `clone` does? The second is cleaner on paper and
   adds a third auto-trust path to maintain; the first is today's exposure.
4. Keep the `-c diff.ignoreSubmodules=dirty` switch as defence in depth on
   unwrapped machines, or remove it (step 5)? Keeping it keeps
   `SWITCH_EXEMPT` and its claims tests alive; removing it is the
   simplification this design is for. Proposed: remove, the verification
   of 3.7 being the replacement.
5. The Rust port: not a condition of this design, but the per-child floor
   is its first concrete justification. Not before the design has settled
   on this branch.
