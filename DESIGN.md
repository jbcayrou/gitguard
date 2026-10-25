# gitguard — design record

**`gitguard.py`** is the whole program: one file, Python 3 standard library
only, Linux and macOS (Python ≥ 3.9, tested on 3.12 and 3.14). This file is
the design record: threat model, what is checked and why, the decisions
that were ruled out, and the history of the bypasses found (numbered `[n]`,
catalogued in `tests/attacks/__init__.py`). README.md is the user-facing
version; CLAUDE.md the working rules, with a map of this file.

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
gitguard retrust       re-validate in bulk the "ok" or "legacy" repositories; anything
                       modified is skipped
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
todo files are read instead, [36]). `/usr/bin/git-receive-pack`,
`git-upload-pack` and `git-upload-archive` are symlinks to `/usr/bin/git`
(Debian): diverted, they land on gitguard, which recognises them by
`argv[0]` (`passthrough`, the one closed list of invocations run without a
check, each with its proof in the code) and passes to the real git — sshd runs them for
every push and fetch *to* the machine, they serve a repository named by
argument (a bare one, not handled) and run nothing of the caller's; a
local push already reaches them unwrapped through the exec path. Found on
the Debian VM: every ssh push to the host failed with "unknown command
'/home/user/srv.git'". `git --version` / `git version` pass through as
well: `version` has no `RUN_SETUP` in git.c, so no repository config,
pager or alias is read (`test_version_runs_nothing_of_the_repository`,
with `git -p version` as the checked control), and lazygit and fugitive
run them first and took the refusal for an old git. Nothing else is on
that list: a subcommand that "only reads" still reads the config.

### Environment variables

`GITGUARD_STATE` (state directory; else `$XDG_STATE_HOME/gitguard` when that
variable is absolute, as the spec requires, else `~/.local/state/gitguard`),
`GITGUARD_REAL_GIT`,
`GITGUARD_ALLOW_REBASE_EXEC`, `GITGUARD_NO_PROMPT` (never ask on the
terminal, refuse directly), `GITGUARD_WAIT` (seconds a git without a
controlling terminal waits for `gitguard pending`, default 60, 0 = never),
`GITGUARD_NO_NOTIFY` (no desktop notification), `GITGUARD_DEBUG` (full
traceback of an internal error, otherwise a neutralized message and exit 1,
git not run), `NO_COLOR`.

Git's own repository-local variables are honoured as git honours them,
because each one moves a file gitguard reads: `GIT_DIR`/`GIT_WORK_TREE`
([28]), `GIT_COMMON_DIR` (the common dir in discovery and once open, the
`commondir` file ignored; absolute only, a relative value is refused — git
reads it against the cwd during discovery and against the root afterwards,
two directories in one run) and `GIT_INDEX_FILE` (the index whose gitlinks
are read; relative to the work tree root git chdirs to, `Repo.index`)
([54]), `GIT_OBJECT_DIRECTORY` (discovery only: objects are volatile and run
nothing, `GIT_ALTERNATE_OBJECT_DIRECTORIES` likewise needs nothing),
`GIT_CEILING_DIRECTORIES`, `GIT_DISCOVERY_ACROSS_FILESYSTEM`,
`GIT_CONFIG_*` ([48]), `GIT_TEMPLATE_DIR` ([42]). The sandbox cannot set
them; a script or a tool of the user can, with a value naming a path of the
volume.

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
   that. The walk stops where git's does: never into a
   `GIT_CEILING_DIRECTORIES` entry that is a proper ancestor of the cwd
   (entries canonicalised until an empty one, `_ceiling_offset`), never
   onto another device unless `GIT_DISCOVERY_ACROSS_FILESYSTEM` — before
   that, a tmpfs mounted inside a modified repository, or a ceiling, made
   gitguard refuse on a repository git would not have opened (parity
   tests; the mount checked on the VM). With `--git-dir`/`GIT_DIR`, the checked tree is
   `--work-tree`/`GIT_WORK_TREE`, else `core.worktree`, else the cwd ([28]).
   `--work-tree`/`GIT_WORK_TREE` alone leaves discovery to the cwd ([18])
   and then names the tree, before `core.worktree`, as
   setup_explicit_git_dir does; the discovered tree was checked instead
   ([72]). A missing one is refused. A `GIT_DIR` that is no git directory
   (missing, or a directory without a valid HEAD, objects and refs) leaves
   git outside any repository, as setup_explicit_git_dir does: nothing is
   checked, no local config exists for git. The global option `--bare` is
   a `GIT_DIR` too: git sets it to the cwd as it is at that point (after the
   `-C` before it), unless one is already set, and a `--git-dir` overwrites
   it; taken for an inert flag, gitguard checked the `.git` of the cwd while
   git read a `config` laid out in the tree's root ([97]). Every global flag
   gitguard lets through is checked against git's choice of gitdir
   (`tests/test_claims.py`).
   `GIT_COMMON_DIR` enters the recognition as it enters git's: `objects`
   and `refs` are looked up there, so a lone `HEAD` makes any directory a
   gitdir — refused as bare ([54]). Without them, a `core.worktree` in the config (common `config`, then
   `config.worktree` if `extensions.worktreeConfig`) redirects the tree as
   git does ([47]) — not in a linked worktree (a `commondir` file or
   `GIT_COMMON_DIR`): git applies it only `if (!has_common)`, and a
   submodule's linked worktree took `.git/modules/<x>` for its tree ([76]).
   With `extensions.worktreeConfig` git reads this gitdir's `config.worktree`
   (its value wins) and clears has_common, so the value applies even there.
   One reader for both paths, `_core_worktree` (git's `check_repo_format`):
   the last value wins and the value is taken **as is** — git copies it
   (`xstrdup`), expands neither `~` nor a variable, and dies on `chdir
   '~/t'`, so a value naming no directory is refused rather than checked
   on an expanded path git never opens; with `GIT_DIR`, `find_root` kept
   the first value and never read `config.worktree` ([84],
   `test_git_dir_core_worktree_as_git`,
   `test_core_worktree_not_interpolated_as_git`). The state key, `.root`
   and the messages stay on the
   directory holding `.git` (`Repo.anchor`, `Repo.label`): a `core.worktree`
   written by the sandbox is an ordinary config change shown in the diff,
   not a "never trusted" repository.
2. **`open_repo`** (`read_gitfile`): `.git` must not be a symlink; if it
   is a `gitdir:` file, the target must not be *inside* the work tree
   (legitimate worktrees and submodules point outside). The common dir is
   `GIT_COMMON_DIR` when set (`env_common_dir`, [54]), else what
   `commondir` names, else the gitdir. The gitfile and
   `commondir` are read as git reads them (`_read_path_file`): bytes, every
   trailing CR/LF trimmed and nothing else, `gitdir: ` at byte 0, then a
   strict resolve (an OS walk, not a lexical `x/..`). A blank, a lone CR or a
   second line are part of the path for git, which dies there; `splitlines()`
   / `strip()` made gitguard check a repository git never opens ([53],
   `test_gitfile_read_like_git`, `test_commondir_read_like_git`).
3. **`check_structure`** (refuses before anything else):
   - `core.splitIndex` (`sharedindex.*` present, or the index's `link`
     extension): explicit refusal, the gitlinks live in a file
     `index_gitlinks` does not read ([31]). The parser applies git's own
     rule to the index extensions: a signature starting with a lowercase
     letter is required, git dies on one it does not know, because it
     changes what the entries mean — so does gitguard
     (`KNOWN_REQUIRED_EXTENSIONS`: `sdir` only). A future one is a refusal,
     not a blind spot.
   - **Sparse index** (`sdir`): a directory outside the cone is one entry,
     mode 040000, naming a tree whose gitlinks the parser cannot see
     (objects are not read). git expands that entry once the directory is
     on disk; the sandbox wrote the tree, a sparse index and a repository
     there, and `git status` ran its fsmonitor ([87]). A sparse directory
     present on disk is walked for a nested `.git` (`index_nested`), the
     same rule as at a gitlink; an absent one, the normal state, costs
     nothing.
   - **`Repo.gitfiles`** = nested `.git` declared in `.gitmodules`
     (`gitmodules_gits`) ∪ targeted by an **index gitlink** (`index_gitlinks`,
     a DIRC v2/3/4 parser, never calling git; a gitlink names its directory
     wherever it is, `node_modules/pkg` included). The width of an object id
     in the entries comes from the repository's format, read as git's
     check_repository_format reads it (`object_id_size`: `config` alone, no
     include; `extensions.objectFormat` only under
     `core.repositoryformatversion`; a value other than `sha1`/`sha256`
     anywhere, or a format git dies on, is refused): a
     SHA-256 index was parsed with 20-byte ids and refused as forged ([63],
     `OBJECT_FORMAT_VARIANTS` with git as the oracle). **No walk of the tree**
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
     rm --cached <dir>`. **The same rule inside every submodule**
     (`check_indexes`, `check_nested_git`): the gitlinks of
     `modules/<x>/index` and the `.gitmodules` of the submodule's tree
     (from its `core.worktree`) name nested repositories that must have a
     gitfile under `modules/<x>/modules/` — `git status` of the
     superproject recurses into the submodule, then into what its index
     names, and runs that repository's config ([60]). Not for a linked
     worktree's index: nothing recurses into another worktree.
   - **Index entry names** (`forged_entry`, `verify_path`, run by the index
     parser on every index of the repository: its own, `modules/<x>/index`,
     `worktrees/<x>/index` — `check_indexes`): git validates a name when it
     reads a tree into the index, never when it writes a file from the
     index, so a forged `.git/index` entry `.git/hooks/post-checkout`,
     `./.git/…`, `x/../.git/…`, `../x` or `/abs/x` is written as is by
     `checkout -- .`, `restore --worktree`, `checkout-index`, and the hook
     runs in the same command ([55]). `verify_path` is a port of git's, with
     `core.protectHFS` and `core.protectNTFS` both on whatever the platform
     (git refuses the same names at `add`, so a legitimate index never holds
     them), checked name by name against `git update-index --cacheinfo`
     (`test_verify_path_matches_git`). Cost: ten substring scans over the
     joined names, ~30 ms once on a 96k-entry index, then cached. The way
     out named by the refusal: delete the index, `git reset` rebuilds it
     from the commits, which git validates.
   - `check_rebase_todo`: no `exec`/`x` line in `rebase-merge/git-rebase-todo`,
     `rebase-apply/git-rebase-todo` or `sequencer/todo` — these files live in
     volatile directories (git rewrites them at every step, they cannot be
     fingerprinted) but git executes their `exec` lines. Any blank after the
     command word counts (`exec<TAB>…`, [35]), and the todo files of every
     nested gitdir root (`modules/<x>`, `worktrees/<x>`, `gitdir_roots`) are
     read too: `submodule foreach 'git rebase --continue'` runs an unwrapped
     git ([36]). The same function refuses a merge strategy outside git's
     builtins (`ort`, `recursive`, `resolve`, `octopus`, `ours`, `subtree`) in
     `rebase-merge/strategy` and in `sequencer/opts` (`[options] strategy`,
     cherry-pick/revert): on `--continue` git execs `git-merge-<name>` for any
     other name — an empty one included —, skipping the validation of a plain
     `git merge -s`, and a `/` in the name makes it relative to the cwd, a
     script of the work tree ([51]). The value is compared as git reads it:
     one trailing newline trimmed, read as bytes, no `strip()` (`ort<TAB>` and
     `ort<CR>` are other names). `GITGUARD_ALLOW_REBASE_EXEC=1` for people who
     run `rebase --exec` or a custom strategy.
   - no control character in a watched name; no symlink in the first two
     levels of the gitdir; `config` and `hooks/` (of the gitdir and of the
     commondir) belong to the user and are not world-writable; no path named
     by the config reached through a symlink in the tree. Outside the tree
     a symlink is ordinary (Homebrew, Debian alternatives, stow): refused,
     it blocked every repository ([75]); a replaceable one is watched as a
     link, whose hash holds its target string and the content it reaches,
     so repointing it or a link behind it is seen. A link to a directory
     stays refused, its content would escape the fingerprint.
   - a watched file must be its **only name** (`_hard_link`): git writes
     many files of the gitdir in place, by name — `COMMIT_EDITMSG`,
     `MERGE_MSG`, `FETCH_HEAD`, the sequencer's files, a reflog it appends
     to — and they are volatile; `.git/COMMIT_EDITMSG` hard-linked to
     `hooks/commit-msg` passed the check with the trusted bytes, then
     `commit --amend` wrote the sandbox's message into the hook and ran it
     ([88]). A symlink there was refused; a hard link is a regular file to
     lstat. Checked inside the tree, the gitdir and the common dir only:
     the sandbox can only `link()` what its mount holds, so both names of
     a link it made lie there; a program the global config names elsewhere
     (Homebrew ships hard-linked binaries, on the same volume as `$HOME`
     on macOS) is left alone, nothing the sandbox writes shares its inode.
   - every file of the repository git reads (config, gitfile, `commondir`,
     HEAD, index, todo files) goes through `read_file`: opened
     `O_NONBLOCK`, anything but a regular file refused at once (a FIFO, a
     socket, a device, a symlink to one; `/dev/null` reads empty). A FIFO in
     place of `.git/config` blocked gitguard for ever — fail closed, but a
     denial of service that pushes the user toward the real git ([99]).
   - an unreadable directory makes gitguard **refuse** (`os.walk(onerror=…)`)
     instead of being seen as empty. A directory that **vanished** during the
     walk (`FileNotFoundError`) is ignored: it holds nothing any more.
4. **Fingerprint** (`manifest`) compared with the reference.

## What the fingerprint watches in the gitdir: everything but the volatile

`walk_gitdir` does not list what it watches: it hashes **everything** in the
gitdir (files and symlinks, at any depth, including `modules/` and
`worktrees/`) and excludes only what git rewrites in normal operation —
directories `objects/??`, `pack`, `refs`, `reftable` ([64]), `logs`,
`lfs`, `rr-cache`, `rebase-*`, `sequencer`, `commit-graphs`; files `index`,
`*.lock`, `HEAD`,
`*_HEAD`, `MERGE_*`, `BISECT_*`, `COMMIT_EDITMSG`, `EDIT_DESCRIPTION`, `packed-refs`,
`shallow`, `gc.*`, `info/refs`, `info/sparse-checkout` ([83]), `objects/info/packs`…
An unknown file or directory is
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
([37]). Plus two **sh readings** (`_sh_readings`) that, between them,
contain every path sh can build without running something gitguard cannot
know: one takes the WORD of each `${X:-WORD}`/`${X:+WORD}`/`${X=WORD}`…
and `.` for each `$(…)`/`` `…` `` and each variable the environment does
not hold (`$(pwd)/t.sh`, `x=$(pwd); $x/t.sh`, an alias's `$1`); the other
takes the variables' values and nothing for a substitution ([58]: these
forms were left as text naming no file, and `$(pwd)` resolves on any
machine). A superset, like includeIf followed whatever its condition: an
extra hash costs nothing, a missed path ran a planted script
(`SHELL_EXPANSIONS`, git as the oracle). **A directory is only retained for
the keys that read its content** (`DIR_KEYS`: `core.hooksPath`,
`init.templateDir`, plus a local remote's `hooks/`), at any depth (a hook
sources `lib/common.sh` next to it) **except a directory that contains the
repository** (`..`, `~`), walked at depth 1: git runs `<hooksPath>/<hook>`
and nothing of the tree from there. Walked recursively, `core.hooksPath =
..` fingerprinted the whole volume — the work tree, the gitdir without its
volatile exclusions, gitguard's own state — and every commit, then every
`trust`, alerted ([65]); the state directory is never entered, and a config
path inside it is refused. A `core.hooksPath` (or `init.templateDir`) **resolving to the root
of the tree** is refused, the way out named (a subdirectory): every
top-level file would be a hook, and the root is never fingerprinted as a
whole ([59]: `$(git rev-parse --show-toplevel)` as hooksPath left
`<root>/pre-commit` unwatched). git executes files, and a
directory in any other value is a program argument (`safe.directory =
~/projects`, `remote.origin.url = /local/repo`, `!make -C src`). **A file
is not retained for the keys whose value git reads as data** (`DATA_KEYS`,
the mirror of `DIR_KEYS`: `user.signingKey`, `gpg.ssh.allowedSignersFile`,
`core.excludesFile`, `core.attributesFile`, `commit.template`,
`blame.ignoreRevsFile`, `mailmap.file`, `diff.orderFile`, `http.sslKey`…):
a closed list, each key documented by git as a path to a file it, ssh-keygen
or curl reads and never runs. The generic rule took `user.signingKey =
~/.ssh/id` (ssh signing) for a program: hashed on every command, copied into
every `<key>.d/ext/`, each rotation refused every repository, and `restore`
wrote the old key over the new one ([56]). Program keys (`gpg.program`,
`core.sshCommand`, `credential.helper`) stay under the generic rule, so a
key named as their argument (`ssh -i ~/.ssh/id`) is still watched. The
first fix kept a 0600 `ext` file out of the state directory; since
2026-10-21 **no `ext` entry is copied, restored or deleted**: `restore`
acts on the gitdir and the tree only, names what it leaves outside, and
the state directory never holds a file from outside the repository.
Exception, a **local remote** (`remote.*.url`/`pushurl` = a path or
`file://` to a repository, `_local_remote`): `push` runs its hooks and
honours its config, so its `config` and `hooks/` are watched (scope `ext` or
`wt`) and that config is parsed like the others — but its own remotes are
not followed ([45]); +1.4 ms per command with one local remote. The remote
is **opened as receive-pack opens it**, a port of `enter_repo`: `<p>/.git`,
`<p>`, `<p>.git/.git`, `<p>.git`, the gitfile followed, then `commondir`,
without the environment (git clears it for the transport); the config and
hooks/ are the common dir's, its relative values (`core.hooksPath =
.husky/_`) resolve against its gitdir, where enter_repo chdirs ([67]) — and
so do the values of the global and system config, which git reads in the
remote too, and in every submodule's tree; the environment's and `-c`'s in
the submodules only, where git carries GIT_CONFIG_PARAMETERS ([68]). Every
key, not the DIR_KEYS alone: a global `hook.<n>.command = ./scripts/pc.sh`
(git 2.54) ran `sub/scripts/pc.sh` during `submodule update` ([92]). Read
again there, a token counts only as an explicit relative path (`./x`,
`scripts/x`): a bare word is run from the PATH, an absolute one was seen
at the root, and every word of the global config (`user.name = t`) matched
a file of each submodule. Not covered: a bare-word *argument* of a global
program (`sh pc.sh`) in a submodule, the [71]/[74] boundary; aliases are
not read again (git runs one where the user types it, and a git run from a
submodule is checked with it as root) — a
`file://` URL is read as parse_connect_url reads it — percent-decoded
whole, the host part dropped (`file://host/p`, `file://[a/b]/p`) ([69]) — and
`remote.pushDefault`, `branch.<b>.pushRemote` and `branch.<b>.remote` are
followed like `remote.*.url` (a name no section defines is a URL for git,
[73]). The gitfile, `commondir` and
`config.worktree` are watched too ([61]: a planted `commondir`, a gitfile
remote, a worktree as remote moved what git runs elsewhere;
`test_local_remote_hooks_git_runs_are_watched` asks git which hook it
runs). In exec mode, **`git push <path>`** to a local repository that no
trusted config names is refused, the way out named (`git remote add`,
`trust`): its hooks are watched for nobody ([62]). The destination is read
like git's parse-options reads `push` (`--repo`, abbreviated long options,
`-o` and its value; a relative path from the root); the repository itself
(`push . main:x`) and the path of a configured remote pass. A configured
remote is a name the trusted config gives a url or pushurl: a `[remote "x"]`
section without one (a global `remote.origin.prune`) is no remote for git,
which takes `x` as a path ([82]). `git archive
--remote=<path>` gets the same check ([70]: upload-archive runs the
remote's `tar.<format>.command`), its option read as cmd_archive reads it
(no abbreviation, last one wins, `--no-remote`, `-o`/`--output`/`--exec`
values, nothing after `--`); from a directory that is no repository, where
nothing names remotes, it is checked too, relative to the cwd, and the way
out is `git -C <path> archive` ([81]).
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
the value, a C string). `~user/` is expanded like `~/` ([50]). The file is read as bytes: text mode
turned a lone CR into a line break where git keeps it inside the value ([52]). The cost is
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
volume was a complete bypass ([16]). These files are **parsed, never
hashed**: the sandbox cannot write them, whoever can (`$HOME` mounted) can
write the state directory too, and hashing them turned every registered
repository "modified" at each `git config --global` or `git lfs install`
([56]; a former scope `global`, with a grouped review in `retrust`, is
gone). A reader of one global setting (`safe.bareRepository` for the
warning, `init.templateDir` for auto-trust) goes through
`iter_global_config`: the same files and the files they include, so that a
setting kept in an included file is seen — `safe.bareRepository = explicit`
there drew the warning anyway ([85]). Last, the **config git takes from its
environment and command line** (`env_config`: `GIT_CONFIG_PARAMETERS` in
both of git's quoting syntaxes, `GIT_CONFIG_COUNT`/`GIT_CONFIG_KEY_n`/
`VALUE_n`, and in exec mode the `-c`/`--config-env` of the command,
`CLI_CONFIG`/`CLI_CONFIG_ENV` set by `apply_global_options`): the sandbox
cannot write it, but a value may name a path in the volume ([48]). A
relative `include.path` from there is ignored, as git refuses it. The `-c` and
`--config-env` an **alias** carries (`ci = -c core.hooksPath=.githooks
commit`) are that config too: git applies them on every run of the alias,
so they go through the same reading, from whichever file defines the alias
([80]), in either form git reads: `[alias] ci = …` or, since git 2.54,
`[alias "ci"] command = …` ([90]).

**How a value names a path, as git reads it.** A pathname value (git's
`git_config_pathname`: `core.hooksPath`, `init.templateDir`…) may start
with `:(optional)` (git 2.52): the path, the variable unset when it does
not exist; exactly that prefix, once, case-sensitive — `:(Optional)x` is a
path. gitguard watched `<root>/:(optional).githooks` ([91]). Not for
`include.path`, which git opens as written. A relative `include.path`
inside an included file resolves against that file **as git opened it**:
through a symlink, the link's directory, not the target's ([94]); the files
are queued as opened, canonicalised only to be hashed. One file is read
once per (file, base, origin), not once: a `~/team.gitconfig` included by
the superproject's config and a submodule's has its relative values
resolved in each, and one included by the local and the global config
keeps its global origin ([93]). A token is a candidate after each letter
of a leading short option too (`ssh -F./c`, `-vF./c`: `-v`, then `-F`
holding the rest): the whole word was dropped and ssh read a file nobody
watched ([96]).

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
`check_structure`). The config diff splits lines on LF only, as git does
(`_config_lines`): with `splitlines()` a lone CR became a line break and
`hooksPath = .githooks<CR>x = y`, one value for git, showed as two clean
lines before `[y/N]` ([53]).

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
`ConfigScan` (one pass over every config source: `refs`, what the config
makes git read outside the gitdir; `remote_names`; `cmd`, the aliases;
`add` records a path, `consider` reads one entry, `run` orders the
sources; `config_refs(repo)` builds one; `DIR_KEYS` for the keys that
accept a directory; `global_config_files` / `iter_global_config` for the
system/global config); `manifest` (dict `(scope, path) → Entry`) with
`walk_gitdir` and `walk_tree`; `inspect(repo) → Inspection` runs the three
in the only safe order (scan, structure, fingerprint) for every caller —
`main`, `entries`, `review_pending`, `retrust`, the auto-trust of
`run_git` — and `save_trust(repo, refs, man)` takes an Inspection's
`refs` and `new` with no default, so the state blessed is always one that
was computed and shown. `gitdir_paths` is the **only** walk of the
gitdir (volatile pruned): the fingerprint and the control-character scan of
`check_structure` both use it. The volatile rules live **once** in
`_child_root` / `_zone` / `_volatile_dir` / `_volatile_file`, shared by
`walk_gitdir` and `gitdir_excluded` (two copies had drifted apart: flaw [22]).
`Manifest` (version/root/refs/entries, `current`) ← `load_manifest`;
`load_pending` / `update_pending` (flock on the state directory) / `record_pending` / `caller_chain` /
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
`wt` (tree), `ext` (outside the tree, writable).

## Storage

`$XDG_STATE_HOME/gitguard/`, i.e. `~/.local/state/gitguard/` (mode 700;
XDG's home for per-machine, non-portable state), key = first 16 hex digits of the
sha256 of the root's absolute path:

```
<key>           reference manifest
<key>.d/        backup of the watched files (.root, local/…, common/…, wt/…); an
                `ext` file is hashed but never copied: restore never writes
                outside the repository [25] [56]
<key>.idx       cache of the index parse: version, then one record per index file
                of the repository (its own, modules/<x>, worktrees/<x>: sha256 of the
                file, object id width + gitlinks [63]), rewritten by any check
                when an index changes; a
                record only exists for an index whose names passed verify_path [55],
                an older version is ignored; never a source of trust
<key>.pending   a refusal nobody read (exec mode, no controlling terminal): kind
                (changed/never/structural), message, the state seen (changed),
                the waiting pids and their calling processes; read by `pending`
<key>.tmp, <key>.d.tmp, <key>.idx.tmp, <key>.pending.tmp   being written (swapped in by rename)
```

The read-modify-write of a `.pending` record is serialised by a flock on
the state directory itself (an fd of it), not on a `<key>.pending.lock`
file: such a file can never be removed (unlinking it under a holder lets a
third process take a second "exclusive" lock on a fresh inode) and every
`trust` left one behind for ever ([57]). `prune` also removes the
`.pending` record of a never-trusted repository that no longer exists
(it has no manifest, so `list` and `entries()` do not see it) and the
lock files of earlier versions.

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
The options are read as git's parse-options reads them (`NEW_REPO_OPTIONS`,
`_long_option`): any unique prefix of a long option is that option, `--no-`
forms negate, a short cluster ends at its first letter taking a value.
`--templ=<dir>` copied the template's hooks and the new repository was
trusted with them ([98]); anything that may stand for `--template`, an
ambiguous prefix included, now counts as it. The table is held to `git
clone -h` and `git init -h` of the git under test (`tests/test_claims.py`).
With a template we warn and leave a manual `gitguard trust`; bare, mirror
and `--separate-git-dir` are silently left alone (a bare repository cannot
be trusted at all).

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
   check, it is the next command that accepts. Same for
   `branch.<x>.vscode-merge-base` (value a ref name: no leading `-`, no
   blank), which VS Code's git extension writes on opening a repository —
   every repository turned "modified" on first open in code-server; git
   ignores the key, VS Code passes the value to `git merge-base`. A closed
   list of three harmless keys, **not** a blocklist: do not extend it
   without a demonstration that the key cannot execute anything
   (`branch.x.rebase`, `remote.*.url`, a lone comment: refused → prompt). A `config` that differs only by comments
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

## Tools that run git, as observed (Debian 13 VM, system-wide install)

Every git a prompt or a TUI spawns from a terminal session inherits the
controlling terminal (`ps -o tty=` says `pts/N`), so on a modified
repository it is refused at once, no `pending` record, no wait: starship
(three calls per prompt, `config -lz` and `for-each-ref` with `--git-dir`/
`--work-tree`/`-c core.fsmonitor=`; branch still shown, from libgit2),
oh-my-zsh (`command git rev-parse` synchronously, then the dirty check in a
`<( )` worker that *does* keep the tty — `tty=?` only showed during session
teardown), fish, `__git_ps1`, lazygit (dies with gitguard's message in its
error), tig ("Not a git repository"). powerlevel10k runs no git at all:
`gitstatusd` reads `.git` itself, shows branch and status whatever gitguard
thinks, executes nothing. vim/fugitive runs its first git (`config --list`)
as a job without a terminal: that one waits `GITGUARD_WAIT`, then `:Git
status` (with the tty) prints the refusal inside vim. pre-commit's hook
runs under the real git's exec path (`HOOKGIT=/usr/lib/git-core/git`); the
four wrapped calls seen came from `pre-commit install`, before the hook
existed. cron: `PATH=/usr/bin:/bin`, no tty, waits the default 60 s,
records `sh ← cron ← cron`; the `%` of a `date +%s` in a crontab is a
newline, not a gitguard matter. `git lfs install` writes four
`filter.lfs.*` keys into the global config: while that file was hashed,
every registered repository turned "modified" at once (first with one
unreadable line, then with a diff and a grouped review in `retrust`); since
[56] the global config is parsed, not hashed, and the command is silent.
root running git in a user's repository
gets "suspicious owner/permissions" on `config` (the file is not root's)
and an empty state of its own. A rootless podman container writing as its
root (= the user's uid) plants hook, config and include in one go; as uid
1000 inside (subuid outside) it cannot write into `.git` at all.

## Nested repositories: the gitlink is the barrier, no walk of the tree

gitguard never walks the work tree looking for nested `.git`. git opens a
nested repository through a gitlink: those of the index, which gitguard
always reads (`index_gitlinks`; a sparse directory of a sparse index is
looked at on disk, [87]), and those a command brings from a tree (below:
[66], [77]–[79], [86]; [89] still open). This section first said "only
once a gitlink references it in the index": that premise was wrong seven
times, so read every "never" here as a claim to test. The `git add -A`
that creates an index gitlink executes nothing by itself — verified for `add -A`, `add .`,
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

**The gitlink that arrives with the command** ([66], fixed on 2026-10-23;
[77]–[79] on 2026-10-24). The barrier above holds for a gitlink already in
the index. The sandbox can also plant an untracked repository `vendor/x`
(its config running a script) and a commit whose tree has a gitlink there,
and move a branch — or forge `refs/stash` — to it: objects and refs are
volatile, nothing is in the fingerprint, and the index gitguard reads has
no gitlink. Some commands write the gitlink, then report the state of the
tree in the same process: `checkout` / `switch` print the local changes,
`stash pop` runs `git status`; `merge`, `rebase`, `pull` with an autostash
re-apply it and print the status; `cherry-pick` and `revert` with the
editor list the status in the message template ([77]). That report asks
each gitlink whose directory holds a repository whether it is modified by
running `git status` inside it (is_submodule_modified), which honours the
planted config — all in the one command whose check passed. Probed command
by command on git 2.47.3 and 2.50: `reset` (every mode), `restore`,
`read-tree -u`, `bisect`, `am`, `apply --index`, `merge --squash`,
`checkout -f`/`-q`, a merge or rebase without autostash write the gitlink
without entering it. Fix: in exec mode, **every** command runs with `-c
diff.ignoreSubmodules=dirty` inserted after the user's global options
(`with_ignored_submodule_dirt`; the last `-c` wins, so a user's `=none`
does not reopen it), except the commands of SWITCH_EXEMPT (below). git
then compares each gitlink's recorded commit and skips the `git status`
in the submodule (match_stat_with_submodule; `submodule.<name>.ignore`
does not override it, override_submodule_config). The gitlink is written;
the **next** command sees it and is refused, as after an `add`. The
option travels to children through GIT_CONFIG_PARAMETERS, so a hook these
commands run, and the git a shell alias runs, see it too.

The switch was first applied to a list of the entering commands
(`checkout`, `switch`, `stash`, then [77]'s merge, rebase, pull,
cherry-pick, revert), which needed `help.autocorrect` modelled — git's
parse_autocorrect and a port of help_unknown_cmd's weighted Levenshtein
([78]) — to catch a typo git turns into one of them. That list failed
open: every command it missed was a bypass ([77] came right after [66]),
and a future git can add an autostash or a status summary to another
command. Since 2026-10-24 the default is inverted: the switch is on
unless the command is known to be harmless *and* to show the option's
effect. `SWITCH_EXEMPT` = `status`, `diff`, `config`, `var`:
probed on git 2.50 with a dirty submodule, every form of each command,
with and without the option — status (long, `--short`, `--porcelain`) and
diff (`--submodule=short/log` too) report the submodule's dirty tree,
`config --list`, `config <key>` and `var -l` list the command-line config;
`submodule summary` and `status`, `describe --dirty`, `show`, `stash`,
`add`, `ls-files` and the diff plumbing are unchanged. None of the four
writes a gitlink into an index. `commit` was exempt too, "it writes the
index from the work tree" — which is how a gitlink gets in ([86], review
of 2026-10-24): `commit -a`, a pathspec or `-i` stage a tracked file the
sandbox replaced by a repository (typechange 100644 → 160000), a partial
commit (`commit <path>`, `-o`, `--amend <path>`) resets a temporary index
from a HEAD the sandbox moved to a commit with a gitlink, and the message
template (or `--dry-run`, `-v`) then ran `git status` in it. Each
exemption is now a claim with a test: every [86] form against each exempt
command (`tests/test_commands.py`). A command missing from the exemption
costs a line of output, never a bypass; a wrong exemption is a bypass.
What changes for the user: `status`, `diff` and `config` behave as
before, directly or through an alias every
definition of which resolves to one of them; every other command, a
shell alias (`!git status`) and a word gitguard does not know (a typo
help.autocorrect fixes, an alias it cannot resolve) get the switch — the
summary of a checkout or a `!git status` no longer flags a submodule
whose own tree is merely dirty (new commits are still shown); the
Levenshtein port and `_autocorrect_on` are gone.

Which command runs is read as git reads it, from the repository's own
config, the global files and `-c` (`CmdConfig`, filled by config_refs;
`exempt_from_switch`): an alias is split as split_cmdline splits it
(`_split_cmdline`) and its leading global options skipped as
handle_options does (`-p`, `-c`, `--config-env`; git dies on the others)
([79]); a builtin is never shadowed; an alias may name an alias; every
definition counts rather than modelling precedence, and all of them must
resolve to an exempt command for the alias to be exempt (an alias loop
resolves to nothing: switch). A shell alias (`!…`) runs git from git's
exec-path, which git puts first on the alias's PATH — never the wrapper,
even installed as documented — so its words are candidate commands
(`_shell_alias_words`, `git-` dropped): candidates, not an interpretation
of sh, the boundary of [71] and [74]; `git` is no exempt command, so a
shell alias is never exempt. Ruled out: reading the target tree before
the command (an object reader — zlib, packs, deltas — for one case),
restoring the tree walk (above), `=all` (hides submodules from the report
altogether), asking git for its command list (`git --list-cmds`: running
git on the repository being judged), the switch on every command without
exemption (it would change `status` and `diff`).

Performance (M4 Pro, see PERF.md for the full tables): ~33 ms overhead per
command, constant whatever the tree: interpreter 16 ms, stdlib imports 6 ms,
**compiling the script 15 ms** (a script run by path is never cached as
`.pyc`; only an `import` is), gitguard's own work ~2 ms. The imports are
kept to what every command needs; `subprocess`, `shutil`, `difflib`,
`termios`, `fcntl` and `dataclasses` were 12 ms of imports paid by every
check and are now imported where used (trust, restore, pending, the
prompt). The one size-dependent cost was the Python parse of the
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

**`python3 -m pytest`** (~1060 tests, expected failures [44], [71], [74] — accepted limitations — and
the open [89], [95]; ~180 s, ~40 s with `-n 8` on the command line),
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
  (config parser, path expansion, includes, alias tokens, discovery — ceiling
  directories included —, index gitlinks, config file origins) gitguard must
  read too. The discovery tests carry the `discovery` marker: `pytest -m
  discovery` after a git upgrade re-checks the ports of setup.c (the
  section header in gitguard.py maps each function to its git original;
  the suite's header names the git used as the oracle). Checked so far
  against git 2.47.3 (Debian 13) and 2.50.0 (Homebrew). Known divergences
  are marked `xfail(strict=True)`: the suite stays green, a fix makes the
  test XPASS so the mark gets removed and the scenario promoted to
  `tests/attacks/`. See "Known limitations" for the list.
- `tests/test_claims.py` — **gitguard's closed lists of claims about git,
  held to git**: each global flag of `GLOBAL_FLAGS` leaves the gitdir where
  git puts it ([97]), every form of each `SWITCH_EXEMPT` command leaves a
  gitlink brought from a tree alone ([86]), `NEW_REPO_OPTIONS` is `git
  clone -h` / `git init -h` ([98]), the indexes git writes carry no
  required extension the parser refuses ([87]). Each of these lists fell
  in a review because the tests checked the known attacks, not the claim;
  a list added to gitguard.py gets its test here.
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

gitguard has been through fourteen adversarial review passes (the numbered
catalogue in `tests/attacks/__init__.py` is their output: 99 bypasses and
false positives, two of them RCEs found after the tool was believed solid,
[58]–[65] from the tenth and eleventh, replayed and fixed on 2026-10-22;
[66]–[70], [72], [73], [75], [76] from the twelfth, fixed on 2026-10-23;
[77]–[83] from the thirteenth, fixed on 2026-10-24; [84], [85] from a
design review; [86]–[99] from the fourteenth (six agents, 2026-10-24),
fixed on 2026-10-25 but [89] and [95], open;
[44], [71] and [74] are accepted limitations, see "Known limitations"; the ninth pass was the
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
6. **Replay the fix too, with variants, before believing it.** A green test
   proves only what it exercises. The [51] fix was validated by its own test
   four times while a `strip()`, an empty name, a lone CR and a swallowed NUL
   each let the real git through; every gap came out of a shell loop over
   byte variants (`\t`, `\r`, `\v`, `\0`, a trailing blank, a second line)
   run against the real git on the VM. Any reader of a file git reads gets
   that loop, and the loop becomes a parity test with git as the oracle
   (`PATH_FILE_VARIANTS`, `TODO_EXEC_VARIANTS`).

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

**Lessons distilled.** A closed list in gitguard.py ("these flags are
inert", "these commands never enter a gitlink", "these are clone's
options") is a claim about git: give it a test with git as the oracle
(`tests/test_claims.py`) when it is written — [86], [97] and [98] were
each a list entry nobody checked. A principle fixed for one key or one
case ([68] for DIR_KEYS) is a bypass for the next ([92], [93]): apply it
to the unit it is about (the file, its base, its origin). Mirror git's discovery order exactly rather than
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
  dropped by the sandbox remain, to be inspected by hand. It never acts
  outside the repository: an `ext` entry (`../shared-hooks`, a program
  under `$HOME`) is named and left as is, whatever its state — two flaws
  were restore writing there ([25] deleted neighbours, [56] overwrote a
  rotated key). In the tree it never deletes outside the roots the
  **trusted** config designates (an `include.path = ../evil.inc` planted
  with the hook is left in place and named, the rest is restored — refusing
  the whole restore left hook, config and include in place).
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
  `xfail(strict=True)`; none is open at the moment (the former ones, [46]
  to [50], and the sh expansions of [58] are fixed). Deliberate divergences,
  fail-closed: NUL in a config
  (refused, git truncates), a bad config line (refused, git dies).
  `core.bare = true` in a non-bare layout is not handled (git then has no
  work tree).
- **Accepted limitation [44]** (decided 2026-10-23, xfail test kept as the
  record: `test_checkout_rewrites_tracked_hook_then_runs_it`): hooks
  **tracked in the tree** under `core.hooksPath` (husky, `.githooks`,
  lefthook). The container needs no `.git` write: it commits a rewritten
  `post-checkout` (or `pre-commit`, `pre-push`…) and moves a branch to it,
  or leaves it for the next `pull` — objects and refs are volatile. The
  files on disk and the config are still the trusted ones when gitguard
  checks; `git checkout`/`merge`/`pull`/`reset --hard` of that commit
  writes the new hook, then runs it, in the same command. Its general form,
  the gitlink brought by the command ([66]), had a switch (`-c
  diff.ignoreSubmodules=dirty`); a tracked hook has none: git runs the file
  as checked out. Ruled out: forcing git onto the trusted copy (`-c
  core.hooksPath=<backup>`) — husky v9's `.husky/_/h` runs `.husky/<hook>`
  from the tree anyway, and hooks that load neighbouring files would break;
  reading the target tree before the command — an object reader (zlib,
  packs, deltas) for this case, and for `pull` the tree is not local yet;
  the tree walk — the file changes only during the command. Why accepted:
  versioned hooks are the user's decision to execute what the repository
  contains, the same boundary as `make` or `npm install` after a pull;
  gitguard guards `.git`, not that choice. Mitigations in place: `gitguard
  trust` warns when a hooks directory is in the tree and says to review
  incoming changes to those files; the prevention layer is a global
  `core.hooksPath` outside every tree (CLAUDE.md), which git's local config
  can still override — a trusted repository's `.git/config` naming
  `.githooks` is the user's own. `OPEN` in `tests/test_attacks.py` is the
  place for a future open attack that fits the corpus.
- **Accepted limitation [71], [74]** (adversarial review of 2026-10-22,
  xfail tests kept as the record): an alias of the user's own, already
  trusted, that runs a script **of the work tree** reached through a `cd`
  (`!cd tools && ./lint.sh`, `!(cd tools; sh lint.sh)`, [71]) or through
  an unset variable glued inside a word (`!sh ./tools$NOPE/lint.sh`,
  [74]). The config does not change — the sandbox rewrites the script,
  which the sh readings ([58]) did not name, and the tree is not walked.
  Not fixed, on purpose: the readings enumerate candidates, they do not
  interpret sh, and a shell can build a path in endless ways (`$(cat f)`,
  `eval`, a script calling another); each variant closed would invite the
  next, and the alternative — refusing every construct gitguard cannot
  resolve — is a blocklist. The exploit needs an alias that assumes one
  repository's layout (rare in `~/.gitconfig`, which serves every
  repository; a local one lives in `.git/config`, fingerprinted), known to
  the sandbox beforehand (it reads `.git/config`, not `~/.gitconfig`), and
  then run by the user. The toplevel idiom (`cd "$(git rev-parse
  --show-toplevel)" && ./scripts/x`) is covered. Way out: name the script
  from the root (`!./tools/lint.sh`) or keep it outside the tree. **Rule:
  the sh readings are not extended for further variants of this shape
  unless a review shows a realistic one.** [67]–[70], [72], [73], [75],
  [76] from the same review are fixed.
- **Open [89]** (review of 2026-10-24): the submodule content diff. With
  `diff.submodule = diff` (global) or `--submodule=diff`, `git show`, `log
  -p` and `diff <rev> <rev>` of a commit bringing a gitlink to a repository
  planted in the tree run `git diff` inside it, honouring its config
  (`diff.external`). The switch only drops the dirty-tree probe; the
  command-line option outranks any `-c`. Needs that setting or option from
  the user. xfail record: `test_submodule_content_diff_enters_a_planted_repository`.
- **Open [95]**, the [44] boundary for config: a tracked `.gitconfig` the
  trusted `.git/config` includes (`include.path = ../.gitconfig`). The
  sandbox commits a new version and moves a branch; `git merge` checks it
  out, then its `git maintenance run --auto` reads it. Decision pending:
  an accepted limitation with a `trust` warning, as [44]. xfail record:
  `test_merge_checks_out_a_tracked_include_then_reads_it`.
- `git --work-tree=<other> …` changes the set of hooks git runs, so the
  fingerprint differs from the repository's own tree ([72]): the tree is
  blessed with `GIT_WORK_TREE=<other> gitguard trust` (same state key),
  and switching between trees prompts each time.
- A global `core.hooksPath` (or any config path) that is a symlink to a
  directory outside the tree (a stow-managed hooks directory) is refused
  ([75]): the link would have to be watched apart from the directory it
  reaches. Replace the link by the real path.
- A value whose path sh builds from a command's output other than the
  cwd (`$(cd sub && pwd)/t.sh`, `$(cat f)`) is beyond the sh readings
  ([58]): only the forms that reduce to the top of the tree or to a
  literal word are covered (same family as [71], [74] above). A push destination reached through an alias,
  `url.<base>.insteadOf` rewriting a URL into a local path, or `git
  send-pack` is not checked ([62]).
- Ordinary commands that still prompt once, by design: `git fsck
  --lost-found` writes `.git/lost-found/` — kept watched, because fsck
  writes the dangling blobs' content there by opening each path, through
  a symlink a sandbox would plant (a volatile directory is not checked for
  symlinks below two levels); `git --git-dir=<repo>/.git …` from another
  directory, or a new `git worktree add`, is another tree, hence another
  trust key ([72]); a transient `-c core.sshCommand='ssh -i <key>'` names
  a file, which joins the fingerprint of that command ([48]) and leaves it
  at the next one without the `-c`.
- A `-c`/`--config-env` given to a git that gitguard did not wrap (hook,
  IDE) is invisible — an alias's own `-c` is read ([80]); the one of the wrapped command and the
  environment are read ([48]). Same for the repository-local variables
  (`GIT_COMMON_DIR`, `GIT_INDEX_FILE`…): read from gitguard's own
  environment, which is the wrapped git's ([54]). Program-naming variables
  (`GIT_SSH_COMMAND`, `GIT_ASKPASS`, `GIT_EDITOR`, `GIT_PAGER`,
  `GIT_EXTERNAL_DIFF`, `GIT_SEQUENCE_EDITOR`, `GIT_EXEC_PATH`) are not
  read: a value naming a script of the volume is the same class as a
  `PATH` directory in it (above), not fingerprinted.
- The system and global config files are parsed for the paths they name,
  not hashed ([56]): a global change that names no file of the volume
  (`alias.x = !curl …`, `core.pager`) is not seen. Writing `~/.gitconfig`
  takes the same access as writing the state directory: out of the model.
- gitguard.py has no dependency outside the stdlib (diff via `difflib`); the
  tests need `pytest` and `git`.
- A context without a terminal and without a desktop session (ssh, cron,
  systemd) gets no notification: the record is written, the wait times out,
  `gitguard pending` shows it later. A script runs `gitguard trust` after
  its `remote add`/`worktree add`, or uses the real git if the repository is
  not exposed to a sandbox.
- `caller_chain` is informational: it says which program to look at, never
  decides anything.
