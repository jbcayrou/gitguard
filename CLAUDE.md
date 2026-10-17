# gitguard

**`gitguard.py`** — Python 3 standard library only, a single file, the only
implementation. JSON manifest (version, root, date, typed entries), a complete
git config parser, paths handled as objects. Runs on Linux and macOS
(Python ≥ 3.9, tested on 3.12 and 3.14). A state written by the original bash prototype (`<key>.config`,
text manifest) is reported as "legacy": run `retrust`.

A guard that refuses to run `git` on a repository whose "trusted" files
(`.git/config`, hooks, attributes, alternates…) have changed since the user
last validated them.

## Why it exists (threat model)

Untrusted code gets **write access to a host directory that contains git
repositories**: a sandboxed LLM agent, a container or VM with a bind mount, a
CI runner, a third-party build tool, a project you just cloned. Whatever the
sandbox, writing into the work tree is the whole point, and `.git/` sits
inside it. Malicious code in there can:

- drop a hook into `.git/hooks/`;
- add to `.git/config` a key that runs a command (`core.fsmonitor`,
  `core.sshCommand`, `core.pager`, `diff.external`, `filter.*`,
  `credential.helper`, `alias.* = !…`, `include.path`…);
- write `.git/info/attributes` (filters, diff drivers), `objects/info/alternates`;
- create a nested `.git` in a subdirectory, or replace `.git` with a
  `gitdir:` file pointing to a booby-trapped directory;
- replace `refs/` or `hooks/` with a symlink out of the repository;
- do the same in `.git/modules/<sub>/` (submodules) and `.git/worktrees/<wt>/`.

When the user next runs `git` **on the host**, that code runs with the user's
rights (SSH keys, credentials, shell). That is the sandbox-to-host pivot.

gitguard is a **detection** layer. **Prevention** layers (an AppArmor/seccomp
profile forbidding writes to `/workspace/**/.git/{config,hooks,…}`, a global
`core.hooksPath`, `safe.bareRepository=explicit`, an unmapped uid in rootless
containers) are independent and complementary; gitguard does not try to
replace them. `safe.bareRepository=explicit` deserves to be set in every case:
git then refuses to discover a bare gitdir (flaw [23]) without gitguard's help.

## Design principle: a fingerprint, not a blocklist

We do not look for "evil" in the config (a blocklist of keys chases git CVEs).
We record a **reference fingerprint** of the files that can serve the pivot,
and refuse any deviation. A false negative on those files is impossible; the
price is an explicit `gitguard trust` whenever the user changes their own
config or hooks.

The fingerprint is stored **outside the repository** (`~/.local/state/gitguard/`),
hence outside any mounted volume. Never move it into `.git/`.

## Commands

```
gitguard               check the current repository, exit 1 if suspect or never trusted
gitguard trust         record the current state as the reference (+ backup of the files)
gitguard diff          show what differs from the reference
gitguard restore [-y]  put the watched files back into the reference state
gitguard git <args>    check, then run /usr/bin/git; honours -C/--git-dir/--work-tree;
                       successful clone/init → auto trust; pure branch tracking → accepted
                       on its own; any other change → diff, then a [y/N] question on the terminal
gitguard list          all registered repositories: status (ok/modified/structure/missing/legacy/unknown), date, path
gitguard forget <repo>... | --missing   remove entries (the repository becomes "never trusted" again)
gitguard prune         = forget --missing
gitguard retrust       re-validate in bulk the "ok" or "legacy" repositories (no backup); skips modified ones
gitguard help
```

The management commands (`list`/`forget`/`prune`/`retrust`) read
`<key>.d/.root` to find the path; an entry without `.root` (trusted by an
earlier version) is shown as "unknown" and can only be `prune`d.

Intended deployment: `alias git='gitguard git'` (interactive shell) or a
symlink `~/bin/git → gitguard` ahead of `/usr/bin` in the PATH (the script
detects it is called `git` and switches to exec mode). Variables:
`GITGUARD_STATE`, `GITGUARD_REAL_GIT`, `GITGUARD_PRUNE` (directories ignored
when searching for nested `.git`), `GITGUARD_SCAN_TREE=1` (enables the search
for nested `.git` in the tree, **off by default**, see "Tree scan"),
`GITGUARD_ALLOW_REBASE_EXEC`, `GITGUARD_NO_PROMPT` (never ask on the terminal,
refuse directly), `GITGUARD_DEBUG` (full traceback of an internal error,
otherwise a neutralized message and exit 1), `NO_COLOR`.
After an upgrade that changes what the fingerprint contains: `gitguard retrust`.

## What the script checks, in order

1. **Root discovery without calling git** (`find_root`): walk up the
   directories and at each level, **in git's order**: does `.git` exist? If
   not, is the directory itself a gitdir (`HEAD` + `objects/` + `refs/`,
   `is_bare_gitdir`)? In that second case we refuse: an unhandled bare
   repository, or a booby-trapped directory git would use instead of the
   repository (flaw [23]). Calling `git rev-parse` would already read the
   trapped config — never reintroduce that. With `--git-dir`/`GIT_DIR`, the
   checked tree is `--work-tree`/`GIT_WORK_TREE`, else `core.worktree`, else
   the cwd ([28]).
2. **`resolve_gitdir`** (in `open_repo`): `.git` must not be a symlink; if it
   is a `gitdir:` file, the target must not be *inside* the work tree
   (legitimate worktrees and submodules point outside).
3. **`check_structure`** (refuses before anything else):
   - `core.splitIndex` (`sharedindex.*` present): explicit refusal, the
     gitlinks live in a file `index_gitlinks` does not read ([31]).
   - **`Repo.gitfiles`** = nested `.git` declared in `.gitmodules` ∪ targeted
     by an **index gitlink** (`index_gitlinks`, a DIRC v2/3/4 parser, never
     calling git; independent of `GITGUARD_PRUNE`, a gitlink may target
     `node_modules/pkg`) ∪, only with `GITGUARD_SCAN_TREE=1`, those found by
     walking the tree (outside `GITGUARD_PRUNE`, `nested_gits`). Same rule for
     all ([24]): a `gitdir:` **file** must point under `.git/modules/`
     (submodule) or `.git/worktrees/` (linked worktree stored in the tree,
     [27]); a **directory** is refused, declared or not — git reads its config
     as soon as a gitlink exists, and an ordinary `git add -A` creates that
     gitlink if the nested repository has a commit (proof:
     `tests/nested_git_is_a_threat.sh`). A directory that is a **bare gitdir**
     (`HEAD` + `objects/` + `refs/`, not named `.git`) is refused the same way
     ([23]). Escape hatch for a deliberately vendored repository: `GITGUARD_PRUNE`.
   - `check_rebase_todo`: no `exec`/`x` line in `rebase-merge/git-rebase-todo`,
     `rebase-apply/git-rebase-todo` or `sequencer/todo` — these files live in
     volatile directories (git rewrites them at every step, they cannot be
     fingerprinted) but git executes their `exec` lines.
     `GITGUARD_ALLOW_REBASE_EXEC=1` for people who run `rebase --exec`.
   - no control character in a watched name; no symlink in the first two
     levels of the gitdir; `config` and `hooks/` (of the gitdir and of the
     commondir) belong to the user and are not world-writable; no path named
     by the config reached through a symlink.
   - an unreadable directory makes gitguard **refuse** (`os.walk(onerror=…)`)
     instead of being seen as empty. A directory that **vanished** during the
     walk (`FileNotFoundError`) is ignored: it holds nothing any more.
4. **Fingerprint** (`manifest`) compared with the reference.

## What the fingerprint watches in the gitdir: everything but the volatile

`walk_gitdir` does not list what it watches: it hashes **everything** in the
gitdir (files and symlinks, at any depth, including `modules/` and
`worktrees/`) and excludes only what git rewrites in normal operation —
directories `objects/??`, `pack`, `refs`, `logs`, `lfs`, `rr-cache`,
`rebase-*`, `sequencer`, `commit-graphs`; files `index`, `*.lock`, `HEAD`,
`*_HEAD`, `MERGE_*`, `BISECT_*`, `COMMIT_EDITMSG`, `packed-refs`, `shallow`,
`gc.*`, `info/refs`, `objects/info/packs`… An unknown file or directory is
therefore watched. Accepted consequence: `remote add`, `worktree add`,
`submodule add` require a `trust` (they change `config` or the structure) —
`push -u` / `branch -u` too, but that precise case is accepted on its own in
exec mode (see "Exec-mode shortcuts"); commit, checkout, merge, rebase,
stash, bisect, notes, gc, repack, fsck do not alert. On a false positive for
an ordinary git operation, **add the file to the exclusion list**, never go
back to an inclusion list.

The exclusions are **anchored**: a name from `VOLATILE_DIRS` only counts
directly under a gitdir root — the gitdir itself or a `modules/<x>` /
`worktrees/<x>`, recognised by the presence of a `HEAD` or `commondir` during
the top-down walk (`_child_root`). Without this anchoring, a submodule named
`lfs`, `refs`, `pack`… made its whole gitdir invisible ([15]). Same for
`objects/pack`, `objects/??`, `objects/info/commit-graphs` and the volatile
files, which only count at their real position. A nested root is only
recognised **under `modules/` or `worktrees/`** of a root (a forged
`.git/hooks/HEAD` made `hooks/` a root, [29]); and `VOLATILE_RELPATHS`
(`info/refs`, `objects/info/packs`…) is tested relative to the closest root,
not to the gitdir base (`git gc` in a submodule alerted, [26]).

## What the fingerprint watches outside the gitdir

One entry per file: `(scope, path) → (kind, mode, sha256)`. A **symlink** is
an entry of its own (`kind = l`) hashed by its target string **and** by the
content of the designated file; the walks never follow links; a link added,
removed or redirected therefore changes the fingerprint, at any depth. Scope
`common`: files of the main repository when in a linked worktree (read via
`commondir`).

**Tree files that drive git** (scope `wt`): the root gitfile (linked
worktree), `.gitmodules`, `.lfsconfig` (git-lfs reads
`lfs.customtransfer.*.path` from it, a program it runs — [34]), the gitfile of
each submodule or nested worktree (`Repo.gitfiles`). Tracked or not, a change
requires a `trust`.

**Paths referenced by the config** (`config_refs`): `core.hooksPath` (husky,
lefthook, pre-commit put the hooks in the tree), `include.path`/`includeIf`
**followed recursively** (depth 10, git's `MAX_INCLUDE_DEPTH` — stopping
earlier left a payload at the 7th level), and **any token of a value that
exists as a file** (relative to the root, `./x` or absolute) — `alias.x = !sh
tool.sh` counts, `core.pager = cat` does not since `cat` does not exist in
the tree. **A directory is only retained for the keys that read its content**
(`DIR_KEYS`: `core.hooksPath`, `init.templateDir`): git executes files, and a
directory in any other value is a program argument (`safe.directory =
~/projects`, `remote.origin.url = /local/repo`, `!make -C src`).
Fingerprinting it alerted on every neighbouring file and, worse, `restore`
deleted there ([25]). Under the root → scope `wt`; outside the tree but
writable by the user (e.g. `../shared-hooks` in the same mounted volume) →
scope `ext` with an absolute path; outside the tree and not writable
(`/usr/share/…`) → ignored. Files and symlinks under these paths are hashed
like those of the gitdir. Reason: a sandbox that only has the tree writable
can rewrite `.githooks/pre-commit` without touching `.git`, and the trusted
config executes it. The config is parsed by `parse_git_config`, **never**
with `git config` (git would honour the config we are judging).

**Config files parsed** (not merely hashed): `config` and `config.worktree`
of the gitdir **and of the commondir** (a linked worktree has no `config` of
its own and uses the main repository's), then `/etc/gitconfig` (or
`GIT_CONFIG_SYSTEM`), `~/.gitconfig`, `GIT_CONFIG_GLOBAL`,
`$XDG_CONFIG_HOME/git/config`. Their values name paths the sandbox can write
— a **global** `core.hooksPath` or `include.path` pointing into the mounted
volume was a complete bypass ([16]). The global config is also hashed as is
(scope `global`), but never restored.

## Display and sanitization

`san()` neutralizes the control characters of a text about to be displayed,
**except SGR sequences** (`ESC [ … m`: colour, bold, reset), which can neither
clear the screen, nor move the cursor, nor fake a message. Consequence: `san`
is idempotent on a message already coloured via `STYLE`, and everything can
go through it without precaution — `info/warn/fail/hint` always neutralize,
`Refuse` neutralizes at construction, there is no "raw" mode. `\n` is
preserved (intended in messages; in a file name it is already refused by
`check_structure`).

History: the first version filtered everything in `err()` and printed
`?[31m`; the second had a `raw=True` flag to set by hand, forgotten on the
"never trusted" message. Do not reintroduce a mechanism where the caller has
to remember a rule.

A file name containing an SGR sequence remains a structural violation
(refusal): the only effect it can have is to colour its own name in the
refusal message.

## Organization of gitguard.py

`is_bare_gitdir` / `find_root` (discovery, git's order); `Repo`
(root/gitdir/common, `nested` and `gitfiles` cached) → `open_repo`;
`check_structure` (refuses; `check_split_index`, `check_rebase_todo`);
`config_refs` (what the config makes git read outside the gitdir; `DIR_KEYS`
for the keys that accept a directory; `global_config_files` for the
system/global config); `manifest` (dict `(scope, path) → Entry`) with
`walk_gitdir` and `walk_tree`. `gitdir_paths` is the **only** walk of the
gitdir (volatile pruned): the fingerprint and the control-character scan of
`check_structure` both use it. The volatile rules live **once** in
`_child_root` / `_zone` / `_volatile_dir` / `_volatile_file`, shared by
`walk_gitdir` and `gitdir_excluded` (two copies had drifted apart: flaw [22]).
`Manifest` (version/root/refs/entries, `current`) ← `load_manifest`;
`changes` / `show_changes` / `restore`; `entries` / `cmd_list` / `cmd_forget` /
`cmd_retrust`; exec mode: `split_global_options` (pure, tested) →
`apply_global_options` (chdir, GIT_DIR) and `parse_new_repo`, then `run_git`.
Invoked through a symlink named `git`, `main` strips `argv[0]` (forgotten in
one version: the symlink path went to git, exec mode unusable — tested
since). Every user error is a `Refuse` exception caught in `__main__`
(exit 1). The scopes: `local` (gitdir), `common` (commondir of a worktree),
`wt` (tree), `ext` (outside the tree, writable), `global` (global config,
never restored).

## Storage

`~/.local/state/gitguard/` (mode 700), key = first 16 hex digits of the
sha256 of the root's absolute path:

```
<key>           reference manifest
<key>.config    leftover of the bash prototype, only removed at forget
<key>.d/        backup of the watched files (.root, local/…, common/…, wt/…, ext/…)
<key>.idx       cache of the index gitlinks (sha256 of the file + list), rewritten
                by any check when the index changes; never a source of trust
<key>.tmp, <key>.d.tmp, <key>.idx.tmp   being written (swapped in by rename)
```

The root is canonicalised (`readlink -f`): accessing the repository through
a symlinked path gives the same key. A moved repository becomes "never
trusted" again: intended, a `mv` by the sandbox must not inherit a trust.

## Auto-trust (clone/init)

`parse_new_repo` reads git's global options (`-C`, `-c`…), spots
`clone`/`init` and derives the target directory (2nd positional, or the URL's
basename without `.git`). After git succeeds, `save_trust` is called
**unless**:
- a `.git` already existed in the target before the command (a `git init`
  "reinitialises" without erasing: it would bless a trapped repository);
- `--template=` **or** `init.templateDir` in the global/system config (copies
  hooks from an arbitrary directory the sandbox can write);
- `--bare`, `--mirror`, `--separate-git-dir`.
In those cases we warn and leave a manual `gitguard trust`.

## Exec-mode shortcuts: auto-accept and prompt

When `gitguard git …` finds a deviation from the reference, two shortcuts
before refusing (`check_or_die`, `interactive=True` only in exec mode;
`gitguard` alone remains a diagnostic that reports):

1. **Auto-accept of branch tracking** (`auto_accept` →
   `branch_tracking_only`, pure and tested). If the only deviation is
   `config` (of the gitdir, or of the main repository from a linked worktree:
   scope `common`) and the **semantic** difference between the old `config`
   (backup `<key>.d/<scope>/config`) and the new one is limited to
   additions/removals of `branch.<x>.remote` (value = a remote already
   present in the reference, or `.`) and `branch.<x>.merge` (value
   `refs/heads/…`), gitguard re-trusts on its own, prints one line and runs
   git. This is what `push -u`, `branch -u`, `checkout -b` with
   `autoSetupMerge` write. As `push -u` writes the config **after** the
   check, it is the next command that accepts. A closed list of two harmless
   keys, **not** a blocklist: do not extend it without a demonstration that
   the key cannot execute anything (`branch.x.rebase`, `remote.*.url`, a
   lone comment: refused → prompt). A `config` that differs only by comments
   is not accepted either (empty delta = not for us).
2. **Question on the terminal** (`ask_on_tty`): the diff is shown as before,
   then "Trust this state and run git? [y/N]". Read and written on
   **`/dev/tty`**, never on stdin: git will consume stdin (`apply < patch`,
   `commit -F -`, `update-index --stdin`; tested with `hash-object --stdin`).
   No question — refusal as before — if `/dev/tty` cannot be opened (script,
   IDE, cron), if **stderr is not a terminal** (the diff was not seen), or
   with `GITGUARD_NO_PROMPT`. Never for "never trusted" (nothing to show:
   that would bless an unknown state, explicit `gitguard trust`) nor for a
   structural refusal (raised earlier by `check_structure`, and `trust` would
   refuse it too).

In both cases `save_trust(repo, refs, new)` receives **the state already
computed and shown**: recomputing the fingerprint at the moment of the `y`
would validate what a still-active sandbox could have written between the
diff and the answer. The accepted risk of the prompt is the reflex `y`; the
counter-measure is shortcut 1, which reserves the question for rare changes
(`remote add`, a hook, `include.path`) that the user will read.

Implementation trap: `open("/dev/tty", "r+")` in text mode fails ("not
seekable"); two opens, one for reading, one for writing.

## Tree scan (`GITGUARD_SCAN_TREE`), off by default

Searching the tree for nested `.git` is **off by default**;
`GITGUARD_SCAN_TREE=1` re-enables it. To revisit if a way to make it free
appears.

Why it is acceptable: the walk is only an **early warning**. git opens a
nested repository only when a gitlink references it in the index, which
gitguard always reads (`index_gitlinks`), and the `git add -A` that creates
this gitlink executes nothing by itself — verified for `add -A`, `add .`,
`add <dir>`, `stash -u/-a`, `commit -i`, `status`, `diff`, `clean`, `grep`,
`ls-files -o` (git 2.50). This assumption is **tested**:
`test_first_add_does_not_execute` (pytest, with a positive control) and
`tests/nested_git_is_a_threat.sh`; if a git version breaks it, make the scan
the default again. Without the scan, it is the command that **follows** the
`add` that is refused. Repair: delete `<dir>/.git` **before** `git rm
--cached <dir>` (otherwise `git rm` opens the nested repository). Still read
without walking: `.gitmodules` ([6]) and the gitlinks ([14], [24]).

What is lost, precisely (and only covered by `GITGUARD_SCAN_TREE=1`):

- **A hook or `!` alias of the trusted config that re-invokes git during the
  `add -A`** (`post-index-change` running `git status`, `alias.ac = !git add
  -A && git commit`). git puts `libexec/git-core` at the head of the PATH of
  its subprocesses: the `git` called from a hook or an alias is **always the
  real git**, even with the `~/bin/git` symlink (verified). The gitlink
  already exists at that moment → execution of the nested config.
- **Any git client that is not wrapped** (VS Code re-runs `git status` on
  every file change, lazygit, a Makefile…) between the `add -A` and the next
  wrapped command. With the scan, the `add` was refused and the dangerous
  state never existed.
- A bare gitdir planted in a subdirectory ([23]) is no longer reported from
  the root; `find_root` refuses it as soon as git is run from that
  directory, and **`safe.bareRepository=explicit`** makes git itself refuse,
  wrapped or not. `check_safe_bare` (reading the system/global files with
  `parse_git_config`, never `git config`) warns at `trust`, `retrust` and
  `list` if that setting is missing — not on every command, a repeated
  warning ends up ignored.

`tests/test_attacks.py` replays the corpus in the default configuration and
requires, for each attack, an immediate refusal or — list `DEFERRED`, to keep
up to date — a refusal at the next command; `tests/test_scan_tree.py`
requires that with `GITGUARD_SCAN_TREE=1` everything is refused immediately.

Performance (M4 Pro): ~40 ms floor per command (Python startup 15 ms, stdlib
imports 20 ms), ~65 ms on a 30k-file tree. On a large tree (200k files / 20k
directories, and the Linux kernel — 96k files, 6.3k directories, 10 MB
index) the tree walk by `nested_gits` was ~90 % of the cost (0.6 s for 20k
directories, 0.17 s on the kernel; a C `find` is slower still on APFS, and a
threaded walk gains nothing: APFS serialises `readdir`, 8 threads = 3×
slower). Hence off by default. The second cost was the Python parse of the
index (40 ms for 96k entries): it is cached in `<key>.idx` keyed by the
file's sha256 (4 ms for 10 MB; a byte-pattern shortcut "no 0160000 mode
present" was tried and dropped: in 10 MB of SHAs it appears ~800 times).
Result on the kernel: `git status` 0.28 s → 0.33 s, `git log -1` 6 ms →
48 ms, i.e. the Python floor. With `GITGUARD_SCAN_TREE=1`: +0.21 s. A
directory-mtime cache was ruled out: the sandbox can forge mtimes.

The name scan used to walk the whole gitdir, `objects/` included and twice
(commondir == gitdir): +250 ms on 30k loose objects, and a wrongful refusal
("unreadable directory") when the `git maintenance --auto --detach` launched
by a commit removed `objects/xx` during the walk. Never make a check walk
the volatile parts.

Bugs the tests have already caught, not to be reintroduced: `git gc`
rewrites `info/refs` and `objects/info/packs`; a commit in a submodule or a
worktree modifies `modules/*/index` and `worktrees/*/index`; `core.hooksPath`
into the tree was not watched.

## Tests

**`python3 -m pytest`** (~385 tests of which 26 expected failures, ~100 s),
to run before any change:

- `tests/attacks/` — **the attack corpus**, one module per family (`gitdir`,
  `symlinks`, `worktree_refs`, `nested`, `config_scope`, `tool_itself`). Each
  `attack_*(gg, repo, tmp_path)` function plays the malicious sandbox on a
  clean, trusted repository; its docstring (1st line) is the test name;
  `# [n]` refers to the vulnerability catalogue in `tests/attacks/__init__.py`.
  `test_attacks.py` collects them all and requires a refusal. **Adding a flaw
  = adding a function there, before fixing the code.** `_helpers.py` holds
  the shared constructions (submodule, source repository), not attacks.
- `tests/test_legit.py` — ordinary git operations that must **not** alert
  (false-positive guard: commit, merge, rebase, stash, bisect, gc, worktree,
  submodule, legitimate hooksPath…).
- `tests/test_commands.py` — trust/diff/restore (including the symlink and
  injection guards), auto-trust clone/init, global options,
  list/forget/prune/retrust, sanitized output.
- `tests/test_scan_tree.py` — `GITGUARD_SCAN_TREE=1`: the whole attack corpus
  refused immediately; proof that the first `git add -A` does not execute the
  nested config (positive control); repair; `.gitmodules` read without a
  scan; `safe.bareRepository` warning.
- `tests/test_prompt.py` — auto-accept (real `push -u`, linked worktree,
  refusal as soon as anything else changes) and prompt through a
  pseudo-terminal (`run_with_tty`: setsid + TIOCSCTTY; answers y/n/default,
  trusted state = shown state, git's stdin preserved, no question without a
  tty / with stderr redirected / `GITGUARD_NO_PROMPT` / never trusted /
  structural refusal).
- `tests/test_unit.py` — pure functions: config parser (checked against
  `git config -f` for the ambiguous cases), `parse_new_repo`, `changes`,
  `san`, `Style`, `walk_gitdir` filter, `index_gitlinks` and its cache,
  `branch_tracking_only`.
- `tests/test_git_parity.py` — **git as the oracle**: everything git reads
  (config parser, path expansion, includes, alias tokens, discovery, index
  gitlinks, config file origins) gitguard must read too. Known divergences
  are marked `xfail(strict=True)`: the suite stays green, a fix makes the
  test XPASS so the mark gets removed and the scenario promoted to
  `tests/attacks/`. See "Known limitations" for the list.
- `tests/conftest.py` — fixtures: `gg` (isolated environment: HOME, state,
  global config in `tmp_path`), `repo` (clean trusted repository), `subsrc`.

**`tests/nested_git_is_a_threat.sh`** — standalone bash proof: an undeclared
nested repository does execute code from the root as soon as a gitlink
exists. Not a test of gitguard, a test of git: re-run it if a git version
changes this behaviour.

Rule: any new vector or false positive discovered must first become a test.

## Adversarial review playbook

gitguard has been through seven adversarial review passes (the numbered
catalogue in `tests/attacks/__init__.py` is their output: 31 bypasses and
false positives, two of them RCEs found after the tool was believed solid).
The method that worked, for the next pass — by a human or by agents that know
nothing of the previous ones:

**Method.**
1. Write the attack as a shell scenario against the script: a clean trusted
   repository, the sandbox writes something, `gitguard` or `gitguard git
   status` must refuse. Watch it PASS (i.e. git runs).
2. Turn the scenario into an `attack_*` function in `tests/attacks/` **before**
   fixing the code. The fix is done when the test is red → green and
   `test_legit.py` still passes.
3. Never put an assertion behind `&&` in a proof script: a proof that cannot
   fail proves nothing. The first version of the nested-repository proof
   created the nested repo without a commit (hence no gitlink) and its only
   assertion sat behind `grep -q … && echo` — it "validated" a tolerance that
   was an RCE ([14]).
4. **Replay every report locally before believing it.** Agents produce
   plausible attacks that are wrong (an `include.path = inc.cfg` reported as
   a bypass was relative to the config file's directory, git did not read it
   either), and one of our own "controls" was itself fooled: the config diff
   printed by gitguard contained the payload word, which looked like an
   execution.
5. A positive control for every negative result: when claiming "git does not
   execute X here", also show the case where it does (see
   `test_first_add_does_not_execute`).

**Angles for independent agents** (disjoint, so that each can go deep;
give each one the threat model, the "what is checked" section and the
exclusion rules, not the catalogue):

- *git's config surface*: every key that runs a program or reads a file
  (hooks, `core.*Command`, pager, editor, `diff.*`/`merge.*`/`filter.*`
  drivers, `credential.helper`, `alias`, `include`/`includeIf` chains,
  `lfs.*`, `init.templateDir`, `core.worktree`); config sources gitguard
  might not read (environment: `GIT_CONFIG_COUNT`, `-c`; `GIT_DIR`,
  `GIT_WORK_TREE`, `GIT_CONFIG_GLOBAL/SYSTEM`, XDG); value syntax the parser
  might read differently from git (BOM, comments with trailing `\`, NUL,
  quoting, `~user/`, shell operators inside `!` aliases).
- *gitdir structure*: gitfiles and `gitdir:` redirections, bare gitdirs in
  subdirectories, nested repositories and the gitlink/`.gitmodules` pair,
  `modules/`/`worktrees/` layouts, names colliding with the volatile lists
  (`refs`, `lfs`, `pack`, `HEAD` as a forged root marker), split index,
  rebase/sequencer todo files, anything git rewrites that could carry code.
- *filesystem tricks*: symlinks at every depth and for every kind of target
  (file, directory, dangling, into a volatile zone, into `$HOME`), control
  characters and escape sequences in names, permissions and ownership,
  directories unreadable or vanishing mid-walk, path canonicalisation
  (`readlink -f` vs literal), mount boundaries.
- *gitguard's own logic*: "covered elsewhere" claims (check them against the
  exclusion rules), ordering of checks, global option parsing (`-C`,
  `--git-dir`, `--work-tree`, `--` handling), auto-trust after clone/init,
  the state directory (key collisions, moved repositories, stale caches),
  `restore` as a write/delete primitive, the display as an attack surface
  (spoofed "no changes", colour codes), the prompt (what state is actually
  blessed).
- *false positives*: every ordinary git workflow must stay silent (commit,
  merge, rebase, stash, bisect, gc, maintenance, worktrees, submodules,
  LFS, hooksPath managers); a tool that cries wolf gets `trust`ed blindly.

**Lessons distilled.** Mirror git's discovery order exactly rather than
approximating it; treat every exclusion as a potential blind spot and
cross-check the code paths that assume "already fingerprinted"; anchor
exclusions to a position, never to a bare name; hash what a link designates,
not just where it points; a directory is never watched unless git reads its
content; fail closed on anything the parser cannot make sense of.

## Known limitations (do not "fix" without thinking)

- Only covers invocations that go through the wrapper/alias.
- Race window if the sandbox is still running: it can modify `.git` between
  the check and git's execution. No detection: an earlier `podman ps`
  warning was removed, it cost up to ~600 ms per command and probably missed
  the common case of a mounted parent directory. Stop the sandbox before
  running git on the host.
- `restore` only cleans the pivot vector; objects, commits and tree files
  dropped by the sandbox remain, to be inspected by hand.
- A trusted hook that invokes a program by name (`node`, `python`) depends on
  the user's `PATH`; if a `PATH` directory is in the mounted volume, that is
  out of gitguard's reach.
- A tree path referenced indirectly (environment variable, hook script that
  `source`s another) is only watched at the first level: we hash what the
  config names, not what that file loads.
- `.gitattributes` in the tree is tracked content, not watched; it is not
  enough to execute code (filters are defined in the config). `.gitmodules`
  and `.lfsconfig` are watched but tracked: a legitimate change requires a
  `trust`.
- Bare repositories: not handled, refused (`find_root`). A bare gitdir in a
  subdirectory is not seen from the root (except with `GITGUARD_SCAN_TREE=1`,
  and never in a pruned directory); it is refused as soon as git is run from
  that directory, and by git itself with `safe.bareRepository=explicit`.
- Tree scan off by default: a nested repository is only seen at the gitlink,
  see "Tree scan" for the two residual cases (hook/alias re-invoking git
  during the `add`, unwrapped git client).
- `core.splitIndex`: refused (gitlinks in `sharedindex.*`, not read).
- Known parity gaps with git, documented as `xfail(strict=True)` in
  `tests/test_git_parity.py`: config set through the environment
  (`GIT_CONFIG_COUNT`/`GIT_CONFIG_KEY_n`, `-c`) is not read; `core.worktree`
  in `.git/config` is ignored for the root (git resolves a relative
  `core.hooksPath` there); `~user/` is not expanded; a tree script reached
  through a shell operator in an alias (`./tool.sh&&true`, `f() { ./tool.sh; }`)
  is not watched; an invalid `.git` directory (no HEAD/objects/refs) stops
  discovery where git walks past it; the parser diverges from git on a UTF-8
  BOM, a trailing `\` on a comment line, a trailing `\` at EOF and NUL in a
  value (the last one fails closed).
- gitguard.py has no dependency outside the stdlib (diff via `difflib`); the
  tests need `pytest` and `git`.

## Ideas not done

TOFU mode (trust on first use) outside the exposed paths, through a
`GITGUARD_STRICT` variable listing the directories mounted into sandboxes.
