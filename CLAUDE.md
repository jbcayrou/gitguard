# gitguard

**`gitguard.py`** is the whole program: one file, Python 3 standard library
only, Linux and macOS (Python ≥ 3.9, tested on 3.12 and 3.14). This file is
the design record: threat model, what is checked and why, the decisions
that were ruled out, and the history of the bypasses found (numbered `[n]`,
catalogued in `tests/attacks/__init__.py`). README.md is the user-facing
version.

A guard that refuses to run `git` on a repository whose "trusted" files
(`.git/config`, hooks, attributes, alternates…) have changed since the user
last validated them.

## Why it exists (threat model)

Untrusted code runs in a container or VM with **a host directory mounted
into it, and that directory contains git repositories**: a CI runner, a
build of a project you just cloned, a third-party tool, a sandboxed LLM
agent. Whatever the sandbox, writing into the work tree is the whole point,
and `.git/` sits inside it. Malicious code in there can:

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
gitguard pending [<repo>... | -a | -c <repo>...]   decisions waiting for a git blocked by a program:
                       list; review (diff + calling process) and allow/refuse; clear
gitguard forget <repo>... | --missing   remove entries (the repository becomes "never trusted" again)
gitguard prune         = forget --missing
gitguard retrust       re-validate in bulk the "ok" or "legacy" repositories (no backup); skips modified ones
gitguard help
```

The management commands (`list`/`forget`/`prune`/`retrust`) read
`<key>.d/.root` to find the path; an entry without `.root` (trusted by an
earlier version) is shown as "unknown" and can only be `prune`d.

### Deployment

A symlink `~/bin/git → gitguard` ahead of the real git in the PATH: the
script detects it is called `git` and switches to exec mode. This also wraps the tools that run git by name: shell prompts
(oh-my-zsh uses `command git`, which skips aliases), editors, build tools,
which fire a planted `core.fsmonitor` at `cd` time. `alias git='gitguard
git'` only wraps what the user types.

System-wide (Debian): `dpkg-divert` the real git to `/usr/bin/git.real` and
symlink `/usr/bin/git → gitguard`. macOS keeps the PATH symlink
(`/usr/bin/git` is under SIP, renaming Homebrew's git is undone by `brew
upgrade`) plus VS Code's `git.path`.

Pre-existing repositories get one explicit `trust` each, by hand, after a
look at their `config` and `hooks/`. **No automatic migration, no
trust-on-first-use**: ruled out, it blesses an unknown first state for the
sole benefit of a one-time migration. Never-trusted repositories are not a
problem of the system-wide install: clone/init through the wrapper
auto-trust, and a repository cloned by an unwrapped git is mostly the
sandbox's own clone, which must be refused.

### Which git runs (`real_git`)

In order: `GITGUARD_REAL_GIT`; else a **`git.real` next to the invoked path
or next to the script** (the divert layout — an environment variable reaches
neither cron, systemd nor a GUI; the sibling wins over the PATH because it
*is* the git the user would have run; a bare `argv[0]` has no directory, the
cwd is never searched); else the first `git` of the PATH that is not
gitguard itself. The former default `/usr/bin/git` ran Apple's git instead
of Homebrew's, with another system config.

That git's system config (`<prefix>/etc/gitconfig`, derived from the
binary's path) is read along with `/etc/gitconfig`: changing the real git
changes the fingerprint (one `trust`). Hooks and `rebase --exec` run by the
real git call `<exec-path>/git`, unwrapped by design (no recursion; their
todo files are read instead, [36]).

### Environment variables

`GITGUARD_STATE` (state directory), `GITGUARD_REAL_GIT`,
`GITGUARD_ALLOW_REBASE_EXEC`, `GITGUARD_NO_PROMPT` (never ask on the
terminal, refuse directly), `GITGUARD_WAIT` (seconds a git without a
controlling terminal waits for `gitguard pending`, default 60, 0 = never),
`GITGUARD_NO_NOTIFY` (no desktop notification), `GITGUARD_DEBUG` (full
traceback of an internal error, otherwise a neutralized message and exit 1,
git not run), `NO_COLOR`.

After an upgrade that changes what the fingerprint contains (`FORMAT_VERSION`):
entries are reported as "legacy", `gitguard retrust` re-validates them.

## What the script checks, in order

1. **Root discovery without calling git** (`find_root`): walk up the
   directories and at each level, **in git's order**: is `.git` a file (or a
   symlink, refused later), or a directory git recognises? If not, is the
   directory itself a gitdir? That recognition is `is_bare_gitdir`, a port of
   git's `is_git_directory`: a valid `HEAD` (symlink to `refs/…`, `ref:
   refs/…` or a hex id, `_validate_headref`) and `objects` + `refs`
   reachable in the common dir (the directory or what its `commondir` file
   names). A `.git` directory git does not recognise is **walked past**, as
   git does — stopping on it checked, and let the user trust, a bogus gitdir
   while git used the parent's ([49]). In the "directory itself is a gitdir"
   case we refuse: an unhandled bare repository, or a booby-trapped directory
   git would use instead of the repository (flaw [23]). Calling `git
   rev-parse` would already read the trapped config — never reintroduce
   that. With `--git-dir`/`GIT_DIR`, the checked tree is
   `--work-tree`/`GIT_WORK_TREE`, else `core.worktree`, else the cwd ([28]).
   Without them, a `core.worktree` in the config (common `config`, then
   `config.worktree` if `extensions.worktreeConfig`) redirects the tree as
   git does ([47]); the state key, `.root` and the messages stay on the
   directory holding `.git` (`Repo.anchor`, `Repo.label`): a `core.worktree`
   written by the sandbox is an ordinary config change shown in the diff,
   not a "never trusted" repository.
2. **`open_repo`** (`read_gitfile`): `.git` must not be a symlink; if it
   is a `gitdir:` file, the target must not be *inside* the work tree
   (legitimate worktrees and submodules point outside).
3. **`check_structure`** (refuses before anything else):
   - `core.splitIndex` (`sharedindex.*` present): explicit refusal, the
     gitlinks live in a file `index_gitlinks` does not read ([31]).
   - **`Repo.gitfiles`** = nested `.git` declared in `.gitmodules`
     (`gitmodules_gits`) ∪ targeted by an **index gitlink** (`index_gitlinks`,
     a DIRC v2/3/4 parser, never calling git; a gitlink names its directory
     wherever it is, `node_modules/pkg` included). **No walk of the tree**
     (see "Nested repositories"). Same rule for all ([24]): a `gitdir:`
     **file** must point under `.git/modules/` (submodule) or
     `.git/worktrees/` (linked worktree stored in the tree, [27]); a
     **directory** is refused, declared or not — git reads its config as soon
     as a gitlink exists, and an ordinary `git add -A` creates that gitlink if
     the nested repository has a commit (proof:
     `tests/nested_git_is_a_threat.sh`). The refusal names the way out: for a
     deliberately vendored repository, inspect its `config` and `hooks`,
     declare it in `.gitmodules`, `git submodule absorbgitdirs` (gitfile under
     `.git/modules/`), `trust`; otherwise delete `<dir>/.git` **before** `git
     rm --cached <dir>`.
   - `check_rebase_todo`: no `exec`/`x` line in `rebase-merge/git-rebase-todo`,
     `rebase-apply/git-rebase-todo` or `sequencer/todo` — these files live in
     volatile directories (git rewrites them at every step, they cannot be
     fingerprinted) but git executes their `exec` lines. Any blank after the
     command word counts (`exec<TAB>…`, [35]), and the todo files of every
     nested gitdir root (`modules/<x>`, `worktrees/<x>`, `gitdir_roots`) are
     read too: `submodule foreach 'git rebase --continue'` runs an unwrapped
     git ([36]). `GITGUARD_ALLOW_REBASE_EXEC=1` for people who run `rebase --exec`.
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
the tree. Tokens come from a whitespace split, a `shlex` split, the whole
value and a split on sh operators and `=` (`&&`, `|`, `(…)`, `f() { …; }`,
`T=./t.sh`), on the value and on its expanded form: `$PWD`, `${PWD}` and
`$(git rev-parse --show-toplevel)` are the root (where a `!` alias runs),
other variables are expanded from gitguard's environment, which git inherits
([37]). **A directory is only retained for the keys that read its content**
(`DIR_KEYS`: `core.hooksPath`, `init.templateDir`): git executes files, and a
directory in any other value is a program argument (`safe.directory =
~/projects`, `remote.origin.url = /local/repo`, `!make -C src`). Exception,
a **local remote** (`remote.*.url`/`pushurl` = a path or `file://` to a
repository, `_local_remote`): `push` runs its hooks and honours its config,
so its `config` and `hooks/` are watched (scope `ext` or `wt`) and that
config is parsed like the others — but its own remotes are not followed
([45]); +1.4 ms per command with one local remote.
Fingerprinting it alerted on every neighbouring file and, worse, `restore`
deleted there ([25]). Under the root → scope `wt`; outside the tree but
writable by the user (e.g. `../shared-hooks` in the same mounted volume) →
scope `ext` with an absolute path; outside the tree and not replaceable
(`_replaceable`: neither the file nor any parent directory writable,
`/usr/share/…`) → ignored. A 0555 script in a writable directory is watched:
it can be unlinked and recreated ([38]); the cost is that a read-only binary
under a user-owned tree named by absolute path (Homebrew Cellar,
`gpg.program = /opt/homebrew/bin/gpg`) is hashed on every command
(~1 ms/MB). Files and symlinks under these paths are hashed like those of the
gitdir. Reason: a sandbox that only has the tree writable
can rewrite `.githooks/pre-commit` without touching `.git`, and the trusted
config executes it. The config is parsed by `parse_git_config`, **never**
with `git config` (git would honour the config we are judging). The parser
is a **character-level port of git's config.c** (`_Src`, `_parse_value`,
`_parse_section`, `_parse_config_text`), checked against `git config -f` in
`tests/test_git_parity.py`: the earlier regex-and-split parser diverged on a
UTF-8 BOM, a `\` ending a comment line, a `\` at EOF, internal whitespace
(git keeps it as is) and on the characters git's `isspace` does not know
(`\v`, `\f`, NBSP — never use `str.strip()` on a config value), each one
hiding a `core.hooksPath` ([46]). A line git dies on ("bad config line")
is **refused** rather than read differently; a NUL byte too (git truncates
the value, a C string). `~user/` is expanded like `~/` ([50]). The cost is
~2 ms for a 17 KB config.

**Config files parsed** (not merely hashed): `config` and `config.worktree`
of the gitdir **and of the commondir** (a linked worktree has no `config` of
its own and uses the main repository's), the `config` of every submodule
gitdir (`.git/modules/<x>/config`, `_submodule_configs`) with its relative
values resolved against **the submodule's tree** (its `core.worktree`):
hashed before, never parsed, so the hooksPath and alias scripts it names were
not watched ([39]), then `/etc/gitconfig` (or
`GIT_CONFIG_SYSTEM`), `~/.gitconfig`, `GIT_CONFIG_GLOBAL`,
`$XDG_CONFIG_HOME/git/config`. Their values name paths the sandbox can write
— a **global** `core.hooksPath` or `include.path` pointing into the mounted
volume was a complete bypass ([16]). The global config is also hashed as is
(scope `global`), but never restored. Last, the **config git takes from its
environment and command line** (`env_config`: `GIT_CONFIG_PARAMETERS` in
both of git's quoting syntaxes, `GIT_CONFIG_COUNT`/`GIT_CONFIG_KEY_n`/
`VALUE_n`, and in exec mode the `-c`/`--config-env` of the command,
`CLI_CONFIG`/`CLI_CONFIG_ENV` set by `apply_global_options`): the sandbox
cannot write it, but a value may name a path in the volume ([48]). A
relative `include.path` from there is ignored, as git refuses it.

## Display and sanitization

**Streams.** gitguard's own output goes to stderr by default (`OUT`): in
exec mode stdout belongs to git, and a refusal is a diagnostic. The
management commands (`trust`, `diff`, `restore`, `list`, `forget`, `prune`,
`retrust`) switch `OUT` to stdout (`set_output`) so that `gitguard list |
grep` works; `warn` and `fail` always go to stderr. Colours follow the
current output stream's tty-ness.

`san()` neutralizes the control characters of a text about to be displayed,
**except the SGR sequences gitguard itself emits** (`ESC[0m`, `ESC[m`,
`ESC[1m`, `ESC[31/32/33/36m`), which can neither clear the screen, nor move
the cursor, nor hide text. Any other SGR is neutralized: conceal (`8`),
background colours or 256-colour fg = bg made the rest of a config line
invisible in the diff shown before `[y/N]` ([43]). Consequence: `san`
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

`_validate_headref` / `is_bare_gitdir` / `find_root` (discovery, git's
order); `Repo` (root/gitdir/common/anchor, `nested` and `gitfiles` cached) →
`open_repo` (gitfile, commondir, `core.worktree`);
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
`load_pending` / `update_pending` (flock) / `record_pending` / `caller_chain` /
`notify_pending` / `wait_for_decision`; `changes` / `show_changes` / `restore`;
`entries` / `cmd_list` / `cmd_forget` / `cmd_retrust`; `review` / `review_pending` /
`cmd_pending`; exec mode: `split_global_options` (pure, tested; knows every
option of git.c `handle_options`, **refuses an unknown one** rather than
guess whether it takes an argument [40]; resolves a relative `--git-dir` /
`--work-tree` from the cwd *after all* `-C`, as git does [41]) →
`apply_global_options` (chdir, GIT_DIR) and `parse_new_repo`, then `run_git`.
Invoked through a symlink named `git`, `main` strips `argv[0]` (forgotten in
one version: the symlink path went to git, exec mode unusable — tested
since). Every user error is a `Refuse` exception caught in `__main__`
(exit 1); an unknown subcommand or a stray argument is one too (a typo used
to fall through to a silent check, exit 0). The scopes: `local` (gitdir), `common` (commondir of a worktree),
`wt` (tree), `ext` (outside the tree, writable), `global` (global config,
never restored).

## Storage

`~/.local/state/gitguard/` (mode 700), key = first 16 hex digits of the
sha256 of the root's absolute path:

```
<key>           reference manifest
<key>.d/        backup of the watched files (.root, local/…, common/…, wt/…, ext/…)
<key>.idx       cache of the index gitlinks (sha256 of the file + list), rewritten
                by any check when the index changes; never a source of trust
<key>.pending   a refusal nobody read (exec mode, no controlling terminal): kind
                (changed/never/structural), message, the state seen (changed),
                the waiting pids and their calling processes; read by `pending`
<key>.pending.lock   flock for the read-modify-write of the record (never removed
                except by forget: unlinking it under a holder would allow two locks)
<key>.tmp, <key>.d.tmp, <key>.idx.tmp, <key>.pending.tmp   being written (swapped in by rename)
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
- `--template=`, **or** a template directory from any source git reads
  (`_template_dir_configured`): `init.templateDir` in the global/system
  config or a file it includes, global `-c`/`--config-env`,
  `GIT_CONFIG_COUNT`/`GIT_CONFIG_KEY_n`, `GIT_CONFIG_PARAMETERS`,
  `GIT_TEMPLATE_DIR` ([42]) — it copies hooks from an arbitrary directory the
  sandbox can write. (clone's own `-c` is applied after the template: no
  effect, verified with git 2.50);
- `--bare`, `--mirror`, `--separate-git-dir`.
In those cases we warn and leave a manual `gitguard trust`.

## Exec-mode shortcuts: auto-accept, prompt, pending

When `gitguard git …` finds a deviation from the reference, three shortcuts
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
   IDE, cron), if **stderr is not a terminal** (the diff was not seen), if
   **stdout is not a terminal** (a `$(git …)` run by a shell prompt has
   stderr on the terminal and stdout on a pipe: a question there would block
   every prompt redraw on a modified repository; the price is that `git log
   | head` is refused instead of asked — rerun without the pipe), or
   with `GITGUARD_NO_PROMPT`. Never for "never trusted" (nothing to show:
   that would bless an unknown state, explicit `gitguard trust`) nor for a
   structural refusal (raised earlier by `check_structure`, and `trust` would
   refuse it too).

3. **Pending decision** (`wait_for_decision`, `cmd_pending`): when the
   process has **no controlling terminal** (`has_tty`: an editor's polling,
   a build tool, cron — nobody reads its stderr), it records the state it
   saw in `<key>.pending` (`record_pending`: kind, message, manifest, refs,
   its pid and the calling processes from `caller_chain`, `/proc` or
   `/bin/ps`), sends one desktop notification (`notify_pending`:
   `/usr/bin/notify-send` or `/usr/bin/osascript` by absolute path, text as
   arguments, `san()`, 3 s timeout, every failure ignored, one per
   `NOTIFY_COOLDOWN`), and **polls the reference** every `WAIT_POLL` for up
   to `GITGUARD_WAIT` seconds. The decision channel is the reference
   itself: `gitguard pending <repo>` recomputes the *live* state, shows the
   diff against the reference (`review`), says so if it moved since the
   block, asks on the tty and saves exactly what it showed; a waiter whose
   own state equals the new reference runs git, any other refuses (fail
   closed). Refusing removes the record: waiters see it gone and refuse.
   After the timeout the record stays and the decision applies to the next
   invocation. Never-trusted and structural refusals are recorded too (kind
   `never`/`structural`, hooked in `main`'s `except Refuse`, `Refuse.recorded`
   avoids a double record) but never waited for nor allowable from
   `pending`. A process that *has* a terminal (shell prompt, script run from
   a terminal) is refused immediately as before: blocking it would freeze
   the shell. `has_tty` does **not** open `/dev/tty`: on macOS, opening and
   closing it in a session leader whose pty master is not read leaves the
   process stuck in its exit (seen in the pty tests); it reads
   `/proc/self/stat` or `ps -o tty=`. A passing check removes a stale
   record; `trust`, `retrust`, `forget` remove it too.

   Ruled out, with the facts: **polkit** (authorises privileged actions and
   authenticates with a password; no privilege here, one-line message, no
   diff, Linux desktop only) and any **GUI question showing the diff**
   (zenity/kdialog/osascript dialog, a spawned terminal, tkinter): on X11
   any client of the display synthesises the click or the `y` (XTEST), so a
   sandbox given the X socket forges the answer; a popping window steals
   focus and in-flight keystrokes; a question outside the moment the user
   asked git for something is what dialog fatigue feeds on. The decision
   stays in a terminal the user opened.

In all cases `save_trust(repo, refs, new)` receives **the state already
computed and shown**: recomputing the fingerprint at the moment of the `y`
would validate what a still-active sandbox could have written between the
diff and the answer. `save_trust` also **verifies each backup copy** against
that manifest (hash of the copy, in STATE; a symlink's copy by its target
string): the manifest would refuse a file rewritten in that window at the
next check, but the backup would have held the attacker's version for
`restore`. With `pending`, that window lasts minutes. `ask_on_tty` flushes
the tty input queue (`tcflush`) before writing the question: a `y` typed
before the diff was on screen cannot answer it. `trust` on a changed
repository shows the diff first (`review`) and asks on a terminal; in a
script it prints the diff and records. The accepted risk of the prompt is
the reflex `y`; the counter-measure is shortcut 1, which reserves the
question for rare changes (`remote add`, a hook, `include.path`) that the
user will read.

Implementation trap: `open("/dev/tty", "r+")` in text mode fails ("not
seekable"); two opens, one for reading, one for writing.

## Nested repositories: the gitlink is the barrier, no walk of the tree

gitguard never walks the work tree looking for nested `.git`. git opens a
nested repository only when a gitlink references it in the index, which
gitguard always reads (`index_gitlinks`), and the `git add -A` that creates
this gitlink executes nothing by itself — verified for `add -A`, `add .`,
`add <dir>`, `stash -u/-a`, `commit -i`, `status`, `diff`, `clean`, `grep`,
`ls-files -o` (git 2.50). This assumption is **tested**:
`tests/test_nested.py::test_first_add_does_not_execute` (with a positive
control) and `tests/nested_git_is_a_threat.sh`; if a git version breaks it,
a walk before the `add` becomes necessary again. It is the command that
**follows** the `add` that is refused. Still read without walking:
`.gitmodules` ([6]) and the gitlinks ([14], [24]). A bare gitdir planted in
a subdirectory ([23]) is not seen from the root: `find_root` refuses it as
soon as git is run from that directory, and **`safe.bareRepository=explicit`**
makes git itself refuse, wrapped or not — `check_safe_bare` (reading the
system/global files with `parse_git_config`, never `git config`) warns at
`trust`, `retrust` and `list` if that setting is missing, not on every
command (a repeated warning ends up ignored).

History: a walk existed (`GITGUARD_SCAN_TREE`, opt-in, with `GITGUARD_PRUNE`
to skip `node_modules` and the like) and was removed on 2026-10-18. What it
bought was only the **window between the user's `add -A` and the next
wrapped command**: a git running there sees the gitlink — a `!` alias
chaining `add -A && commit` in one git process, a `post-index-change` hook,
or an unwrapped client (VS Code, lazygit, a Makefile). All of these are git
invocations outside the wrapper, out of scope by design (first known
limitation), and the walk only helped if a wrapped command happened to run
between the planting and the unwrapped one. For that partial cover it cost
+0.2 s per command on the Linux kernel (6.3k directories; `readdir` is
serialised by APFS, a C `find` was slower, 8 threads 3× slower). A
directory-mtime cache was ruled out (the sandbox forges mtimes); a
**ctime** cache would work (no syscall sets ctime; `utime` bumps it) and
brought the walk to ~7 ms of `lstat` on a synthetic kernel-sized tree, but
was not worth the extra code for a cover that stays partial. The escape
hatch `GITGUARD_PRUNE` was also misleading: the gitlink detection never
depended on it, so a vendored repository stayed refused after adding it —
the real way out is a submodule (`absorbgitdirs`), now named by the message.

Performance (M4 Pro, see PERF.md for the full tables): ~45 ms overhead per
command, constant whatever the tree (Python startup + stdlib imports 32 ms,
gitguard ~13 ms). The one size-dependent cost was the Python parse of the
index (40 ms for 96k entries): it is cached in `<key>.idx` keyed by the
file's sha256 (4 ms for 10 MB; a byte-pattern shortcut "no 0160000 mode
present" was tried and dropped: in 10 MB of SHAs it appears ~800 times).
Result on the kernel: `git status` 247 → 293 ms, `git log -1` 6 → 52 ms;
80–90 ms once after a command that rewrote the index.

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

**`python3 -m pytest`** (~420 tests, 1 expected failure — [44] —, ~100 s),
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
- `tests/test_nested.py` — nested repositories: proof that the first `git
  add -A` does not execute the nested config (positive control); repair;
  the submodule way out (`absorbgitdirs`); `.gitmodules` read without a
  walk; an undeclared nested repository without gitlink is invisible.
- `tests/test_prompt.py` — auto-accept (real `push -u`, linked worktree,
  refusal as soon as anything else changes) and prompt through a
  pseudo-terminal (`run_with_tty`: setsid + TIOCSCTTY, stdout and stderr on
  the pty, `stdout_pipe` for a prompt's `$(git …)`, `pretype` for input
  typed before the question; answers y/n/default, trusted state = shown
  state, git's stdin preserved, pre-typed `y` discarded, no question without
  a tty / with stderr or stdout redirected / `GITGUARD_NO_PROMPT` / never
  trusted / structural refusal).
- `tests/test_pending.py` — a git without a controlling terminal
  (`start_new_session=True`) records and waits; allow / refuse / timeout /
  state moved / two waiters; no wait and no record with a terminal; never
  trusted and structural recorded, not waited; record cleared when the state
  comes back, by `forget`, by `-c`; `pending` without a terminal shows but
  cannot decide. The whole suite runs with `GITGUARD_WAIT=0` and
  `GITGUARD_NO_NOTIFY=1` (conftest).
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
  The scenarios are built with `REAL_GIT`, the first `git` (or `git.real`)
  of the PATH that is not gitguard, put ahead of the fixture's PATH: on a
  machine with the system-wide install, `git` *is* gitguard and every
  scenario was refused as never trusted by the test's own state (77 failures
  on a Debian with `/usr/bin/git → gitguard`).

**Checking `pending` by hand.** A git with a controlling terminal never
waits (`has_tty`), so `nohup … &` or a plain `&` from a shell does not
exercise shortcut 3: both keep the terminal. Detach it: `setsid -w git
status` on Linux; macOS has no `setsid`, use what the tests use,
`python3 -c 'import subprocess, sys; subprocess.run(sys.argv[1:],
start_new_session=True, stdin=subprocess.DEVNULL, stdout=open("/tmp/git.log",
"w"), stderr=subprocess.STDOUT)' gitguard git status &`. Isolate with
`GITGUARD_STATE=/tmp/ggstate`, `GITGUARD_NO_NOTIFY=1` unless the
notification is the point, `GITGUARD_WAIT=300` to have time to run
`gitguard pending <repo>` from another terminal; `cat /tmp/git.log` shows
what the waiter did (`allowed through gitguard pending`, `refused through
gitguard pending`, or `no decision within … s`). The review of a record
without a terminal (`gitguard pending <repo> </dev/null`) prints the diff
and the calling chain but refuses to decide. In zsh, `GG="python3
gitguard.py"; $GG …` fails (no word splitting): put a `gitguard` symlink on
the PATH instead.

**`tests/nested_git_is_a_threat.sh`** — standalone bash proof: an undeclared
nested repository does execute code from the root as soon as a gitlink
exists. Not a test of gitguard, a test of git: re-run it if a git version
changes this behaviour.

Rule: any new vector or false positive discovered must first become a test.

## Adversarial review playbook

gitguard has been through nine adversarial review passes (the numbered
catalogue in `tests/attacks/__init__.py` is their output: 50 bypasses and
false positives, two of them RCEs found after the tool was believed solid;
[44] is still open, see "Known limitations"; the ninth pass was the
promotion of the git-parity `xfail`s [46]–[50]).
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
  dropped by the sandbox remain, to be inspected by hand. It never deletes
  outside the gitdir and the roots the **trusted** config designates (an
  `ext:` path that appeared after the trust pointed into `$HOME`, found in
  review): such a file (`include.path = ../evil.inc` planted with the hook)
  is left in place and named in a warning, and the rest is restored — a
  container planting hook, config and include at once left all three in
  place when the whole restore was refused.
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
  subdirectory is not seen from the root; it is refused as soon as git is
  run from that directory, and by git itself with
  `safe.bareRepository=explicit`.
- No walk of the tree: a nested repository is only seen at the gitlink, see
  "Nested repositories" for what runs in the window between the user's
  `add` and the next wrapped command (a `!` alias chaining git commands, a
  `post-index-change` hook, an unwrapped client) — all outside the wrapper.
- `core.splitIndex`: refused (gitlinks in `sharedindex.*`, not read).
- Parity gaps with git are tracked in `tests/test_git_parity.py` as
  `xfail(strict=True)`; none is open at the moment (the former ones, [46] to
  [50], are fixed). Deliberate divergences, fail-closed: NUL in a config
  (refused, git truncates), a bad config line (refused, git dies).
  `core.bare = true` in a non-bare layout is not handled (git then has no
  work tree).
- **Open [44]**: hooks tracked in the tree under `core.hooksPath` (husky,
  `.githooks`). The container can create objects and move refs (volatile);
  `git checkout`/`merge`/`reset`/`pull` of its commit rewrites the hook
  *after* the check, and git runs it in the same command. Test:
  `test_checkout_rewrites_tracked_hook_then_runs_it` (xfail). `gitguard
  trust` warns when a hooks directory is in the tree. Forcing git onto the
  trusted copy (`-c core.hooksPath=<backup>`) was ruled out: husky v9's
  `.husky/_/h` runs `.husky/<hook>` from the tree anyway, and hooks that
  load neighbouring files would break. `OPEN` in `tests/test_attacks.py` is
  the place for a future open attack that fits the corpus.
- A `-c`/`--config-env` given to a git that gitguard did not wrap (hook,
  alias, IDE) is invisible; the one of the wrapped command and the
  environment are read ([48]).
- gitguard.py has no dependency outside the stdlib (diff via `difflib`); the
  tests need `pytest` and `git`.
- A context without a terminal and without a desktop session (ssh, cron,
  systemd) gets no notification: the record is written, the wait times out,
  `gitguard pending` shows it later. A script runs `gitguard trust` after
  its `remote add`/`worktree add`, or uses the real git if the repository is
  not exposed to a sandbox.
- `caller_chain` is informational: it says which program to look at, never
  decides anything.
