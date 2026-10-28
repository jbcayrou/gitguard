r"""Attack corpus against gitguard.

Each module in this package exposes ``attack_*(gg, repo, tmp_path)`` functions.
Contract: ``repo`` is a clean repository, with one commit, already trusted by
``gitguard trust``. The function plays the malicious container: it may only
modify files (in the tree, in ``.git``, in ``$HOME``) — never call gitguard.
It may however run ``gg.trust(repo)`` *before* planting, to simulate a
legitimate config the victim has trusted (hooksPath, submodule…).

``test_attacks.py`` collects all these functions and checks that gitguard then
refuses to run git. To add an attack: write the function in the module of the
right family (or a new module), nothing else.

Vulnerability catalogue — the ``# [n]`` comments in the tests and in
gitguard.py refer to this list (how the project reviews itself: DESIGN.md,
"Adversarial review playbook"). Numbers 32–33 are unused.

 [1] core.hooksPath pointing into the work tree (husky, lefthook): hooks there
     were not watched at all.
 [2] An added symlink was invisible: `find -type f` skipped it and the
     structural check stopped at depth 2 (hook symlink in
     .git/modules/<sub>/hooks/ or in .githooks/).
 [3] `restore` followed symlinks: `.githooks/pre-commit -> ~/.bashrc` planted
     by the container turned the repair into an arbitrary write.
 [4] A path outside the tree but inside the writable volume
     (`../shared-hooks`) was ignored.
 [5] A relative token without `./` (`!sh tool.sh`) was not recognised as a path.
 [6] `.gitmodules` rewritten to declare a planted `.git` as a submodule (also
     inside a pruned directory such as build/): git descends into it.
 [7] A real submodule's gitfile (`sub/.git`) redirected to a controlled gitdir
     outside .git/modules.
 [8] Chained include.path: only the first level was parsed.
 [9] `find … -quit` checked only the first nested .git.
[10] `git -C /elsewhere`, `--git-dir`/`--work-tree`: gitguard checked $PWD,
     not the targeted repository.
[11] A newline in a file name injected a line into the manifest; `restore`
     read it as an action and deleted .git/HEAD.
[12] Escape sequences in a file name spoofed the display (fake "no changes").
[13] `core.hooksPath = .git/myhooks`: skipped as "already covered by the gitdir
     manifest", which only covered hooks/*. Fix: fingerprint the whole gitdir
     except the volatile parts (deny by default).
[14] "Independent" nested repository tolerated: RCE as soon as a gitlink exists
     in the index (an ordinary `git add -A` creates it). Also a forged index
     whose flags name length differs from the NUL position desynchronised the
     parser and hid a gitlink git honours.
[15] VOLATILE_DIRS applied by name at any depth: a submodule named lfs, refs,
     pack… made its whole .git/modules/<name>/ invisible.
[16] Global config values never resolved to paths (global core.hooksPath,
     include.path, init.templateDir); from a linked worktree the main
     repository's config (commondir/config) was not parsed at all.
[17] include.path chains deeper than 6 (git follows 10); later, a chain of
     exactly 10 was hashed but not parsed.
[18] `--work-tree` alone: gitguard chdir'ed into the work tree to pick the
     repository while git discovers its gitdir from the cwd.
[19] `exec` lines injected into rebase-merge/git-rebase-todo during an
     in-progress rebase (volatile directory, outside the fingerprint);
     REBASE_HEAD missing from the volatile list caused a false positive
     inviting a `trust` that blessed the booby-trapped todo.
[20] `restore` deleted files outside the repository: the hooksPath directory
     replaced by a symlink to $HOME pulled all of $HOME into the fingerprint as
     "added". Fix: refuse config paths reached through a symlink, and only
     delete under the gitdir or under a root the trusted config designated.
[21] `[core]hooksPath = x` on the header line: git accepts a key right after
     `]`, the parser dropped it. Same family: a trailing `foo\\` (even number of
     backslashes) taken for a continuation.
[22] "Covered by the gitdir manifest" was false in volatile zones
     (`core.hooksPath = .git/logs/h`, `include.path = logs/x.conf`): nobody
     fingerprinted them. Symlinks were hashed by their target string only, so
     the target could change freely; a symlink to a directory at depth 3
     (.git/modules/x/hooks -> elsewhere) escaped the structural check.
[23] Bare gitdir (HEAD + objects/ + refs/) planted in a subdirectory: git
     discovers it before the parent's .git when run from there; gitguard
     walked up to the real .git and validated the wrong repository.
[24] Gitfile in a pruned directory + gitlink (`node_modules/pkg/.git` ->
     `gitdir: ../evilgit`): the "gitfile must point under .git/modules" rule
     only applied to .git files found by the tree walk.
[25] A directory named in any config value was fingerprinted whole
     (`safe.directory = ~/projects`): every file added in a neighbouring
     project alerted, and `restore -y` deleted it. Fix: DIR_KEYS.
[26] `git gc` in a submodule alerted: VOLATILE_RELPATHS was tested relative to
     the gitdir base instead of the closest gitdir root.
[27] `git worktree add .worktrees/wt` refused: .git/worktrees/ is a legitimate
     gitfile target.
[28] `--git-dir` + `--work-tree` (or GIT_DIR + GIT_WORK_TREE): the checked root
     was the cwd ($HOME walked entirely).
[29] A forged .git/hooks/HEAD made hooks/ a "gitdir root", excluding its HEAD,
     refs/, logs/, index… from the fingerprint.
[30] `gitguard trust|diff|restore` outside a repository: silent exit 0.
[31] core.splitIndex: sharedindex.* alerted permanently and the gitlinks of the
     shared file were not read. Explicit refusal.
[34] `.lfsconfig` (git-lfs reads lfs.customtransfer.*.path, a program it runs)
     was not watched.
[35] `exec<TAB>cmd` in a rebase todo: git accepts any blank after the command
     word, check_rebase_todo only split on a space.
[36] Rebase todo of a submodule (.git/modules/<x>/rebase-merge) or of a linked
     worktree not read: `submodule foreach 'git rebase --continue'` runs an
     unwrapped git that executes it.
[37] Tree script reached through a sh expansion or operator in an alias
     (`!$PWD/t.sh`, `${PWD}`, `$(git rev-parse --show-toplevel)/t.sh`,
     `T=./t.sh`, `$HOME/bin/t.sh`, `&&`, `|`, `(…)`, `f() { …; }`): not
     recognised as a path, rewritten without alert.
[38] Script outside the tree with mode 0555 in a writable directory: ignored
     because the file itself was not writable, yet unlink + recreate works.
[39] .git/modules/<x>/config hashed but never parsed: the hooksPath and alias
     scripts it names, in the submodule's tree, were not watched.
[40] `git --config-env k=V -C <repo>`: unknown option taking an argument, the
     argument was taken for the subcommand and the -C ignored (gitguard checked
     the cwd, git ran in the trapped repository). Unknown options now refused.
[41] `git --git-dir=.git -C <repo>`: the relative --git-dir was resolved before
     the -C, git resolves it after (another trusted repository was checked).
[42] Auto-trust after clone/init blessed hooks copied from a template given by
     an included global config file, `-c init.templateDir`, GIT_CONFIG_COUNT
     or GIT_TEMPLATE_DIR.
[43] SGR sequences in displayed file content (`ESC[8m` conceal, fg = bg) hid
     part of the config diff shown before [y/N]; only gitguard's own codes
     are kept now.
[44] OPEN — a tracked hook under core.hooksPath in the tree is rewritten by the
     very command the user runs (checkout/merge/reset/pull of a commit the
     container created, refs and objects being volatile), then executed.
     Accepted limitation (2026-10-23, DESIGN.md, Known limitations):
     versioned hooks are the user's choice to run what the tree contains;
     `trust` warns. Test: test_checkout_rewrites_tracked_hook_then_runs_it
     (xfail, the record).
[45] A local remote (remote.*.url = a repository in the volume): its hooks
     run on push, its config is honoured; not fingerprinted. Fix: its config
     and hooks/ (and what that config names), never the whole directory.
[46] The config parser diverged from git's: a UTF-8 BOM, a `\` ending a
     comment line, a `\` at EOF, internal whitespace collapsed, \v / \f /
     NBSP stripped — each one made gitguard miss a core.hooksPath git
     honoured. Fix: a character-level port of git's config.c.
[47] core.worktree in .git/config: git takes that directory as the tree and
     resolves a relative core.hooksPath there; gitguard kept the directory
     containing .git, so those hooks were never watched.
[48] Config from the environment or the command line (GIT_CONFIG_COUNT/KEY_n,
     GIT_CONFIG_PARAMETERS, `-c`, `--config-env`) was not read: a
     core.hooksPath set there, pointing into the volume, was never watched.
[49] Discovery: a `.git` directory git does not recognise (invalid HEAD, no
     objects/refs) stopped gitguard, which checked — and let the user trust —
     a bogus gitdir while git walked up to the parent's; and gitdir variants
     git accepts (HEAD symlink to refs/, `commondir` redirection) were not
     recognised as planted gitdirs [23]. Fix: a port of is_git_directory.
[50] `~user/` in a path value: git expands it (getpwnam), gitguard only
     expanded `~/`, so `core.hooksPath = ~user/vol/hooks` was never watched.
[51] The merge strategy of an interrupted operation sits in volatile files
     outside the fingerprint: `.git/rebase-merge/strategy` (rebase) and
     `.git/sequencer/opts`, `[options] strategy` (cherry-pick, revert). On
     `--continue` git execs `git-merge-<name>` for any name it does not know
     as a builtin, skipping the "available strategies" check of a plain
     `git merge -s <name>`. The name may contain a `/`: `git-merge-/x` is
     relative to the cwd, i.e. a script of the work tree, no PATH access
     needed. check_rebase_todo only read the todo `exec` lines. Fix: refuse
     any strategy outside git's builtin set, same escape hatch as the todo
     (GITGUARD_ALLOW_REBASE_EXEC). Found in review by a reporter; the first
     fix compared a strip()ped value (`ort\t` passed as `ort`, git execs
     `git-merge-ort<TAB>`), skipped an empty name (git execs `git-merge-`)
     and missed sequencer/opts: all caught by replaying on the Debian VM.
[52] parse_git_config read the file in text mode: Python's universal newlines
     turned a lone CR into a line break, where git's parser sees whitespace
     kept inside the value. `hooksPath = .githooks<CR>x = y` is one value for
     git (a directory gitguard never watched); `strategy = ort<CR>x = /y` in
     sequencer/opts passed the [51] check as `ort` while git execs
     `git-merge-ort<CR>x = /y`, a script of the work tree. Found while
     validating [51]. Fix: read bytes, the port of get_next_char already
     handles CRLF.
[53] Other text-mode reads of files git reads, audited after [52]. The
     config diff shown before [y/N] used splitlines(): a lone CR made
     `hooksPath = .githooks<CR>x = y` look like two clean lines. The gitfile
     and `commondir` were read with splitlines()/strip() and a lexical
     resolve(): a trailing blank, a lone CR, a second line or ` ../..` gave
     gitguard a repository where git finds none and dies — no execution,
     but a parity break the suite would have caught. Fix: LF-only split for
     the diff; git's exact reading (trailing CR/LF only) and a strict
     resolve for path files. A NUL in `commondir` is refused, never "not a
     gitdir": git truncates at it and opens the directory, and a planted
     bare gitdir walked past is [23]. The todo files were checked against git 2.47
     and 2.50 and need nothing: whenever git runs an `exec`, gitguard refuses.
[54] Repository-local variables of the environment that move git's files:
     GIT_COMMON_DIR replaces the common dir in every case — during
     discovery (is_git_directory looks for objects/ and refs/ there: any
     directory with a valid HEAD becomes a gitdir) and once open (config,
     hooks/, info/, objects/, worktrees/ come from it, the `commondir` file
     is ignored); GIT_INDEX_FILE replaces the index, hence the gitlinks.
     gitguard read the gitdir's own files and fingerprinted a repository
     git was not using: a hook or a config in a directory of the volume, a
     forged index whose gitlink names a nested trapped repository. The
     sandbox cannot set the variables; a script, a Makefile or a tool of the
     user can, and the value may name a path of the volume. Reported by a
     reviewer. Fix: honour both as git does (an absolute GIT_INDEX_FILE, or
     one relative to the work tree root git chdirs to); a relative
     GIT_COMMON_DIR is refused — git itself reads it against two different
     directories in one run (the cwd during discovery, the root after).
     GIT_OBJECT_DIRECTORY was already honoured in discovery; objects run
     nothing and are volatile, nothing else to read there.
[55] Index entry names that escape the work tree. git validates a path
     (verify_path) when it reads a tree into the index, not when it writes a
     file from the index: `checkout -- .`, `restore --worktree` and
     `checkout-index` write a forged `.git/index` entry as is. Names
     `.git/hooks/post-checkout` (any case on a case-insensitive filesystem),
     `./.git/…`, `x/../.git/…`, `x//../.git/…` land in the gitdir; `../x`
     outside the repository; an absolute name at that very path. The index
     is volatile, the hook is written after the check, and `post-checkout`
     runs in the same command: one write into `.git/index`, no
     core.hooksPath needed. A submodule's index reaches the superproject's
     hooks through an unwrapped `submodule foreach`. The same names in a
     commit's tree are refused by git: the vector is the index. Reported by
     a reviewer, replayed against git 2.50 and 2.47 (oracles:
     test_git_parity.py, section 9). Fix: a port of verify_path (protectHFS
     and protectNTFS on, checked name by name against `update-index` as the
     oracle) run by the index parser on every entry of every index of the
     repository (its own, `modules/<x>/`, `worktrees/<x>/`); the `.idx`
     cache is versioned so that a record written before the check vouches
     for nothing. The refusal names the way out: delete the index, `git
     reset` rebuilds it from the commits, which git validates.
[56] Global config hashed as a whole (scope `global`) and a private key
     watched as a program. Every `git config --global` and `git lfs install`
     turned every registered repository "modified" at once, for a file the
     sandbox cannot write (whoever writes ~/.gitconfig writes the state
     directory too); what the global config *names* in the volume is the
     parse ([16]), kept. And the generic "any token that is a file" rule
     watched `user.signingkey = ~/.ssh/id` (ssh signing: a file ssh-keygen
     reads, never run): the private key was hashed on every command, copied
     into every `<key>.d/ext/`, each rotation refused every repository, and
     `gitguard restore` wrote the old private key over the new one. Fix: no
     `global` scope; `DATA_KEYS` (files git reads as data, mirror of
     DIR_KEYS) not watched; an `ext` file without group/other read bits is
     hashed but never copied nor restored (same trap through
     `core.sshCommand = ssh -i …`, `http.sslKey`…).
[57] State directory litter. The flock for `<key>.pending` lived in a
     `<key>.pending.lock` file that `clear_pending` created on every
     `trust` (nothing pending or not) and that nothing removed, by design
     (unlinking a lock file under a holder lets a third process take a
     second "exclusive" lock on a fresh inode): one file per repository,
     for ever. And the record of a never-trusted repository has no
     manifest, so `prune` never saw it: a deleted repository left its
     `.pending` and its lock behind. Fix: the lock is taken on the state
     directory itself (an fd of it, no file); `prune` removes the records
     whose repository is gone and the lock files of earlier versions.
[58] sh expansions `os.path.expandvars` does not perform, in any value git
     hands to sh (`core.fsmonitor`, `!` aliases, `sequence.editor`, and
     the same values from `-c` or GIT_CONFIG_PARAMETERS [48]):
     `${VAR:-./p.sh}`, `${VAR-…}`, `${VAR:+…}` (also glued,
     `./p.sh${O:+ x}`), `$(pwd)/p.sh`, `` `pwd`/p.sh ``, `x=$(pwd); $x/p.sh`. The value
     named no existing file for _value_tokens, sh resolved it to a tree
     script; `$(pwd)` needs no variable and resolves on any machine. Found
     by an adversarial review, replayed against git 2.50 (macOS) and
     2.47.3 (Debian VM). Fix: two sh readings (_sh_readings), the WORDs
     and `.` for substitutions and unknown variables, then the variables'
     values and nothing; a superset (`SHELL_EXPANSIONS` in
     test_git_parity.py, git as the oracle).
[59] core.hooksPath resolving to the root of the tree (absolute root,
     `.git/..`, `./.`, `root/`): config_refs' add() returned on a path
     equal to the root (meant to avoid fingerprinting the whole tree), so
     no hook was watched and `trust` did not warn about hooks in the tree;
     `<root>/pre-commit` rewritten, `git commit` ran it. `.` and `./` are
     not executed (git searches the PATH and fails with "cannot run
     pre-commit"). Found by an adversarial review. Fix: refused, also from
     the global config, the way out named (a subdirectory such as
     `.githooks`).
[60] Gitlink in a submodule's index (`.git/modules/<x>/index`) naming a
     nested repository inside the submodule's tree: check_indexes parsed
     that index for forged names [55] and dropped its gitlinks; `git status`
     in the superproject recurses into the submodule, then into the nested
     repository, whose core.fsmonitor runs. Same for a nested `.git`
     declared in the submodule's own .gitmodules. Found by an adversarial
     review, replayed against git 2.50 and 2.47.3. Fix: the rule of the
     superproject's nested `.git` (check_nested_git) inside every
     submodule, its gitdir as the root the gitfiles must point under.
[61] Local remote [45] redirected: a `commondir` planted in its gitdir
     (receive-pack takes config and hooks/ from there), a remote whose
     `.git` is a gitfile at trust time (`--separate-git-dir`, a linked
     worktree: _local_remote did not recognise it, nothing was watched),
     `config.worktree` of a remote with extensions.worktreeConfig. Found
     by an adversarial review, replayed; a gitfile planted after trust was
     already refused. Fix: the remote opened by a port of enter_repo
     (suffixes, gitfile, commondir, no environment); the common dir's
     config and hooks/, the gitfile, commondir and config.worktree watched
     (`test_local_remote_hooks_git_runs_are_watched`: git says which hook
     it runs).
[62] `git push <path>` to a repository of the volume not configured as a
     remote: receive-pack ran its hooks; only configured remotes were
     watched [45]. Found by an adversarial review, replayed. Fix: in exec
     mode the push destination is read as parse-options reads it
     (`--repo`, abbreviated long options, `-o` values, relative to the
     root) and a local repository no trusted config names is refused, the
     way out named (`git remote add`, `trust`); the repository itself and
     a configured remote's path pass.
[63] False positive: a `--object-format=sha256` repository could not be
     trusted; _parse_index_gitlinks sized an entry for a 20-byte id and
     refused the index as forged ("inconsistent name length"). Fails
     closed. Found by an adversarial review. Fix: the id width from the
     repository's format, read like git's check_repository_format
     (object_id_size, OBJECT_FORMAT_VARIANTS against git: `config` alone,
     the extension ignored without a version or with -1, kept with -2, an
     invalid value refused wherever it stands, git's integer syntax
     `01`/`0x1`/`1k`); per gitdir: a submodule has its own, a linked
     worktree takes its `commondir`'s.
[64] False positive: `--ref-format=reftable`. `reftable/` (tables and
     tables.list, rewritten on every ref update) was not volatile: every
     commit alerted. Found while replaying [63]. Fix: anchored volatile
     directory, like refs/.
[65] False positive: core.hooksPath naming a directory that contains the
     repository (`..`, `~`). git only runs `<hooksPath>/<hook>`, but
     DIR_KEYS walked the directory recursively: the work tree, its
     neighbours and the gitdir without its volatile exclusions were
     fingerprinted as `ext`, so any commit alerted; with the state
     directory under it (`~` with `~/.local/state/gitguard`), the manifest
     `trust` writes was watched too and the repository alerted again after
     every `trust`. Reported as converging after three trusts; the replay
     showed it did not. Fix: a directory that contains the repository is
     walked at depth 1, the others at any depth as before (a first
     depth-1-everywhere fix stopped watching `.githooks/lib/common.sh`,
     sourced by the hook: caught in review); the state directory is never
     entered, a config path inside it refused.
[66] The gitlink arrives with the command. "The gitlink is the barrier"
     (DESIGN.md, Nested repositories) assumed a gitlink exists in the index
     before the command that opens the nested repository. The sandbox plants
     an untracked repository `vendor/x` (core.fsmonitor), a commit whose tree
     has a gitlink at `vendor/x`, and moves a branch to it (objects and refs
     volatile). `git checkout`/`git switch` to that branch writes the
     gitlink, then shows the local changes, enters `vendor/x` and runs its
     fsmonitor, in the same command; `git stash pop` of a forged
     `refs/stash` does the same through the `git status` it ends with. The
     index gitguard read had no gitlink. No special config, no trust-time
     warning: a generalisation of [44]. `checkout -f`, `reset --hard`,
     `merge`, `pull . main`, `rebase` and `checkout -q` write the gitlink
     without entering it. Found by an adversarial review, replayed against
     git 2.50 and 2.47.3. Fix: `checkout`, `switch` and `stash` — also
     through an alias, global or `-c`, chained — run with
     `-c diff.ignoreSubmodules=dirty`: the summary compares each gitlink's
     recorded commit without running `git status` in it
     (match_stat_with_submodule); the gitlink is written, the next command
     is refused. Tests: test_checkout_brings_a_gitlink_to_a_planted_repository,
     test_stash_pop_brings_a_gitlink_to_a_planted_repository, with the real
     git as positive control; parity of the alias word in
     test_alias_command_word_as_git.
[67] Non-bare local remote with a relative core.hooksPath (husky
     `.husky/_`): receive-pack runs hooks in the remote's $GIT_DIR, so git
     runs `<remote>/.git/.husky/_/<hook>`; gitguard resolved it against
     the remote's work tree. Fix: the remote's relative values resolve
     against its gitdir, where enter_repo chdirs
     (`test_local_remote_relative_hookspath_where_git_resolves_it`: git
     says which hook it runs, every layout).
[68] A global (or system) relative core.hooksPath (`.githooks`) was
     resolved against the repository's root only; git applies it in every
     repository it enters: a local bare remote
     (`hub.git/.githooks/pre-receive` on push), a submodule
     (`sub/.githooks/post-checkout` on `submodule update`). Fix: the
     DIR_KEYS values of global origin are resolved again against every
     local remote's gitdir and every submodule's tree; those of the
     environment and `-c` in the submodules only (git clears
     GIT_CONFIG_PARAMETERS for a local receive-pack, keeps it for a
     submodule). Parity: git says which hook it runs, 17 remote layouts ×
     global/system, and `submodule update --force` with global and `-c`.
[69] `file://` remote URLs are URL-decoded by git (`My%20Repos`),
     not by _local_remote: no repository found, nothing watched; the same
     spelling passed the [62] check of `git push <url>`. Fix: a port of
     parse_connect_url — url_decode on the whole URL (`%XX` once, `%00`
     and invalid escapes kept), the host dropped up to the first `/`
     after a `[…]`; parity layouts for space, lowercase hex, `%2F`,
     `%3A%2F%2F`, `%zz`, `%2520`, `file://host/p`, `file://u@[::1/x]/p`.
[70] `git archive --remote=<local path>` runs upload-archive in
     that repository, which runs its `tar.<fmt>.command` (remote-enabled
     for tgz/tar.gz by default); only `push` destinations were checked
     [62]. Fix: the [62] check also takes archive's `--remote`, read as
     cmd_archive reads it (KEEP_ALL: no abbreviation, anywhere before
     `--`, last wins, `--no-remote`, `-o`/`--output`/`--exec` values).
[71] OPEN — `!cd tools && ./lint.sh`, `!(cd tools; sh lint.sh)`: the token
     resolves against the root (`<root>/lint.sh`), `tools` is dropped as a
     directory, `tools/lint.sh` (what sh runs) is never watched. Accepted
     limitation (DESIGN.md, "Known limitations"): the sh readings
     enumerate candidates, they do not interpret sh; needs a trusted alias
     that assumes one repository's layout. Way out: `!./tools/lint.sh`.
[72] `--work-tree` without `--git-dir` (or GIT_WORK_TREE alone):
     git discovers the gitdir from the cwd and uses the given tree, where
     it resolves a relative core.hooksPath; gitguard checked the
     discovered tree. ([18] fixed the discovery half.) Fix: open_repo
     takes GIT_WORK_TREE as the root after discovery, before core.worktree
     (setup_explicit_git_dir's order); a missing directory is refused.
     The state key stays on the directory holding `.git`, so the tree
     given is trusted through `GIT_WORK_TREE=… gitguard trust`.
[73] remote.pushDefault / branch.<x>.pushRemote / branch.<x>.remote
     naming a path: git pushes to it as a URL; only remote.*.url/pushurl
     were followed, and a bare `git push` has no destination for the [62]
     check. Needs an unusual trusted config. Fix: the three keys are
     followed as local remotes, like remote.*.url.
[74] OPEN — an unset variable glued inside a word (`!sh
     ./tools$NOPE/lint.sh`, `${NOPE}`) expands to nothing in sh; the sh
     readings [58] give `.` or keep the text, never the empty expansion.
     Low realism; accepted limitation with [71].
[75] False positive: add() refused any config path that is itself a
     symlink, outside the tree too: `gpg.program = /opt/homebrew/bin/gpg`
     (Homebrew), `core.editor = /usr/bin/vim` (Debian alternatives), a
     stow-managed `~/.gitconfig.local` refused every repository, `trust`
     included. Fix: refused only in the tree; outside, a replaceable link
     is watched as a link (target string and the content it reaches:
     repointing it, or a link behind it, is seen); a link to a directory
     stays refused.
[76] False positive: a linked worktree of a submodule (`git -C sub
     worktree add`) could never be trusted: open_repo applied the common
     config's core.worktree, which git ignores in a linked worktree, and
     took `.git/modules/<sub>` for the tree (volatile-zone refusal or
     internal ValueError). Fix: core.worktree only without a commondir
     (git's `if (!has_common)`) — or with extensions.worktreeConfig, which
     reads config.worktree and clears has_common; git is the oracle for
     the three cases (`test_core_worktree_in_a_linked_worktree_as_git`).
     Found by an adversarial review (two agents), replayed against git 2.50
     and 2.47.3; each open one has an xfail(strict) test.
[77] The [66] switch covered checkout/switch/stash only. merge, rebase
     and pull with an autostash (rebase.autoStash, merge.autoStash,
     pull.rebase, `--autostash`) and a dirty tree bring the gitlink, then
     re-apply the stash and print the status, entering the planted
     repository; cherry-pick and revert with the editor do the same while
     writing the message template. A common global setting and a plain
     `git rebase`/`git pull`. Fix: these commands join
     ENTERS_NEW_GITLINKS, probed command by command (reset, restore,
     read-tree, bisect, am, apply do not enter); the real git runs every
     form in the positive control.
[78] help.autocorrect defeated the command match: `git chekout main` is no
     command for gitguard, git corrects it to checkout and runs [66]. Fix:
     with autocorrect on (_autocorrect_on, git's parse_autocorrect), a word
     that is no alias gets the switch when an entering command or alias is
     within git's similarity (prefix, or the weighted distance of
     help_unknown_cmd + 1 below 7; _levenshtein is a port) — a superset of
     the one git picks. git is the oracle for 32 typos and 20 values.
     Superseded on 2026-10-24: the switch is the default on every command,
     exempt only status, diff, commit, config and var (SWITCH_EXEMPT,
     exempt_from_switch); a word gitguard does not know gets it, so the
     autocorrect model and the Levenshtein port are gone. The list of
     entering commands failed open ([77] after [66]); the exemption fails
     closed.
[79] An alias whose head is a global option (`co = -p checkout`, `-c
     color.ui=auto checkout`, `--config-env=…`) was read by its first word;
     a shell alias (`co = !git checkout`) not at all — and its inner git is
     the one of git's exec-path, put first on the alias's PATH, never the
     wrapper. Fix: the alias is split as split_cmdline (_split_cmdline,
     whole) and its options skipped as handle_options does (_alias_parts);
     a shell alias's words count as candidate commands, `git-` dropped
     (_shell_alias_words): the outer `-c` reaches its inner git.
[80] The `-c` an alias carries (`ci = -c core.hooksPath=.githooks
     commit`) was opaque tokens to config_refs: git honours it on every
     `git ci`, `.githooks` was not watched, a rewritten hook ran. The same
     `-c` on the command line was refused. Fix: an alias's `-c` and
     `--config-env` pairs go through consider() like the command line's.
[81] `git archive --remote=<path>` from a directory that is no repository:
     no root found, git ran unchecked, upload-archive ran the destination's
     tar.<format>.command ([70] checked it only inside a repository). Fix:
     the same check outside, relative to the cwd; the way out is `git -C
     <path> archive`, checked like any command.
[82] A `[remote "x"]` section without a url (a global `remote.origin.prune
     = true`) made `x` a configured remote: `git push x` was not checked,
     and git, finding no url, takes `x` as a path — `<root>/x`, a planted
     bare repository whose pre-receive ran. Fix: a name counts only with a
     url or pushurl from the trusted config.
[83] False positives: `git branch --edit-description` leaves
     `.git/EDIT_DESCRIPTION`, `git sparse-checkout set/add` rewrites
     `.git/info/sparse-checkout` — the next command was refused every time.
     Both join the volatile lists (a symlink there is still an entry; the
     two-level symlink check covers both places). Not `lost-found/` (`git
     fsck --lost-found`, the same review): fsck writes each dangling blob's
     content to `lost-found/other/<sha>` through a symlink planted there,
     and the sandbox chooses the blob — a hook rewrite; the planted link is
     a new entry, refused (attack_lost_found_symlink_for_fsck, with the
     real git as positive control in test_commands). [77]–[83] found by an
     adversarial review (three agents), replayed against git 2.50 and
     2.47.3.
[84] Parity, discovery: `core.worktree` read differently from git. With
     GIT_DIR, find_root kept the first value (git: the last) and never read
     config.worktree (git: with extensions.worktreeConfig its value wins);
     open_repo and submodule_trees expanded `~` and `~user` (git copies the
     value as is, check_repo_format's xstrdup, and dies on `chdir '~/t'`):
     gitguard checked `$HOME/t`, a tree git never opens. Found in the
     design review of 2026-10-24, replayed against git 2.50. Fix: one
     reader (_core_worktree) for find_root and open_repo, last value wins,
     config.worktree honoured, no interpolation; a missing directory is
     refused as git dies.
[85] False warning: `safe.bareRepository = explicit` set in a file the
     global config includes was not seen (safe_bare_explicit read the
     global files without their includes), so trust/list/retrust warned
     about a setting that was in place. Same review. Fix: the global files
     and their includes read by one iterator (iter_global_config), also
     used by _template_dir_configured.
[86] `commit` in SWITCH_EXEMPT, on the ground that it never writes
     a gitlink from a tree. It does: `commit -a` (or a pathspec, `-i`)
     after the sandbox replaced a tracked file by a repository stages the
     typechange 100644 → 160000; a partial commit (`commit <path>`, `-o`,
     `-v`, `--dry-run`, `--amend <path>`) resets a temporary index from a
     HEAD the sandbox moved to a commit with a gitlink. Either way the
     message template's status enters the planted repository and runs its
     fsmonitor, in the command whose check passed. `-m` renders no
     template. `-c diff.ignoreSubmodules=dirty` keeps git out (checked):
     commit left the exemption.
[87] sparse index (`sdir` extension): a directory outside the cone
     is one 040000 entry naming a tree; the index parser reads entries one
     by one and never sees the gitlink inside that tree (objects are not
     read). The sandbox writes the tree, a sparse `.git/index` and the
     nested repository: git expands the entry once the directory is on
     disk, `git status` runs the planted fsmonitor. Needs a cone
     sparse-checkout. Fix: a sparse directory present on disk is walked for
     a nested `.git` (index_nested); an unknown required index extension
     (lowercase signature, which git dies on) is refused.
[88] hard links. `.git/COMMIT_EDITMSG` (volatile) linked to the
     trusted `hooks/commit-msg` (or to a hook of the tree, a local
     core.hooksPath): at the check the hook's bytes are the trusted ones;
     `git commit --amend` writes the sandbox's commit message into that
     inode, then runs it. A symlink there is refused; a hard link is a
     regular file to lstat, and st_nlink is never looked at. A global
     core.hooksPath outside the volume stops the first form only. Fix: a
     watched file of the tree, the gitdir or the common dir with another name is
     refused (_hard_link).
[89] The submodule content diff. With `diff.submodule = diff`
     (global) or `--submodule=diff`, `git show`/`log -p`/`diff <rev> <rev>`
     of a commit bringing a gitlink to a planted repository run `git diff`
     inside it, honouring its diff.external. `diff.ignoreSubmodules=dirty`
     only drops the dirty-tree probe; `diff` is exempt from it anyway.
     Accepted as a limitation on 2026-10-26 (a setting the user chose,
     rare; `-c diff.submodule=log` would take their display away), then
     closed the same day by the exec-path design (DESIGN-exec-path.md):
     that `git diff` is a child git, `<exec-path>/git`, i.e. gitguard,
     which refuses the planted repository as never trusted. The switch
     (`-c diff.ignoreSubmodules=dirty`), its exemption and the alias
     reading made for it are gone with it; [66] [77] [78] [86] are
     covered by the same child refusal, their scenarios kept.
[90] the subsection form of an alias, `[alias "ci"] command = -c
     core.hooksPath=.githooks commit` (git 2.54): parsed as section
     `alias.ci`, key `command`, never read as an alias, so the `-c` of
     [80] is not seen and `.githooks` is not watched. Fix: read as alias.
[91] `core.hooksPath = :(optional).githooks` (git 2.52+, local or
     global): git strips the `:(optional)` prefix of a pathname value;
     gitguard watched `<root>/:(optional).githooks`, which does not exist.
     Program keys are caught by accident (the sh split on `()`). Fix: the
     prefix stripped (once, case-sensitive, as git) from DIR_KEYS values;
     not from include.path, which git opens as written.
[92] a global config-based hook with a relative command
     (`hook.<n>.command = ./scripts/pc.sh`, git 2.54) runs in every
     repository git enters, a submodule during `git submodule update`
     included. The [68] re-resolution against each base covers DIR_KEYS
     only; a relative program token of global origin is resolved against
     the root. Fix: every global value (aliases aside) is re-resolved.
[93] one config file included by the superproject's config and by
     a submodule's (`~/team.gitconfig`, core.hooksPath = .githooks) is
     parsed once: `seen` is keyed by path, not by (path, base), and its
     relative hooksPath is never resolved in `sub/`. Same for two
     submodules, or a file included by the local and the global config
     (the global flag of [68] is lost). Fix: read once per (file, base,
     origin).
[94] a relative include inside an included file that is a symlink:
     git resolves it against the directory of the file as opened (the
     link's), gitguard against the target's. The sandbox writes the file
     git reads, gitguard watches another. Fix: included files are queued as
     opened.
[95] OPEN — variant of [44] for config: a tracked `.gitconfig` the trusted
     `.git/config` includes (`include.path = ../.gitconfig`). The sandbox
     writes objects and a ref only; `git merge` checks the new file out,
     then spawns `git maintenance run --auto`, which reads it and starts
     its `pager.maintenance` on the user's terminal. Accepted (2026-10-27),
     like [44]: same repository, same command; `trust` names every file the
     config names in the tree. A re-check by the covered child was tried
     and reverted: [124]. Variant [123].
[96] a path glued to a short option (`core.sshCommand = ssh
     -F./deploy/ssh_config`) is one token starting with `-`, dropped;
     ssh reads the file, a ProxyCommand planted there runs on `git fetch`.
     Fix: `-X<path>` yields the candidate `<path>`.
[97] `git --bare <cmd>`: git takes the cwd as its gitdir
     (handle_options sets GIT_DIR); gitguard took `--bare` for an inert
     flag, discovered the repository from the cwd and checked its `.git`,
     while git read a `config` the sandbox laid out in the tree's root.
     Fix: `--bare` sets the gitdir as git does; a GIT_DIR that is no git
     directory means no repository (`git --bare init` still runs).
[98] git's parse-options accepts any unique prefix of a long
     option: `init`/`clone --templ=<dir>` copy the template's hooks, but
     parse_new_repo recognised `--template` only and auto-trusted the new
     repository with them ([42]). Fix: clone's and init's options read as
     parse-options reads them (NEW_REPO_OPTIONS, held to `git <cmd> -h`).
[99] `.git/config` replaced by a FIFO: the config reader blocks in
     read() for ever. Fail closed (git never runs), but a denial of service
     that pushes the user toward the real git; a file git reads that is not
     a regular file is to be refused at once: read_file, O_NONBLOCK.
     [86]–[99] found by an
     adversarial review (six agents, 2026-10-24), replayed against git 2.50
     and 2.54; replayed against 2.47.3 (Debian VM) on 2026-10-26. All fixed
     on 2026-10-25 but [89] (closed on 2026-10-26, exec-path design) and
     [95] (accepted on 2026-10-27).
[100] False positives from the inventory of git's source (tests/inventory.py,
     2026-10-26): every name git opens under a gitdir, held to gitguard's
     tables by test_claims.py. Four edit buffers at the gitdir root were
     neither volatile nor read: `ADD_EDIT.patch` (`add -e`), `NOTES_EDITMSG`
     (`notes add|edit`) when the editor fails (`:cq`), `REPLACE_EDITOBJ`
     (`replace --edit`) when the editor changes nothing — the next command
     was refused, every time, until a `trust`. `MERGE_LABELS` and
     `rebased-patches` are the same class. And three pathname keys git reads
     as data (`fsck.skipList`, `fetch.fsck.skipList`, `receive.fsck.skipList`,
     `http.sslCAPath`) were not in DATA_KEYS: the [56] trap for a file of
     object ids. The method, not a review, found them: the bottom-up
     catalogue above took fourteen passes to cover a universe git's source
     enumerates under five signatures (DESIGN.md, "Tests").
[101] Every clone but of a plain local path (`file://`, ssh, https, a
     bundle, `--depth`, `--bare`, `--mirror`, `--separate-git-dir`) runs
     fetch-pack → index-pack, a child with `GIT_DIR=<new>/.git` from the
     user's cwd; the `new` marker compared the child's root alone, so every
     such clone died "repository never trusted" — or, from a trusted cwd K,
     reported a false diff of K. The suite had never run a clone through
     index-pack. Fix: `new` covers a gitdir, common dir or root under the
     new path; bare and separate-gitdir forms set the marker too (NewRepo).
[102] The marker covered by the name `.git` and by state key
     (`_owner_keys`): a worktree's submodule (`worktrees/<wt>/modules/<x>`),
     a `--separate-git-dir` repository's, a submodule's own submodule
     worked in directly were covered by nobody, every `status` there
     refused. Fix: the marker carries the judged gitdir, common dir and
     root; a child is covered when its gitdir and common dir are both among
     `gitdir_roots` of those — exactly what the walk hashed.
[103] A gitdir planted in a volatile zone of a real submodule's gitdir
     (`.git/modules/sub/refs/p`: hashed by nobody) and named by a gitfile.
     By the submodule's index (volatile): `check_nested_git` accepted any
     target under `modules/`, and `git status` recursed into it — master
     too. By a commit the sandbox writes (a gitlink `vendor/x`): the child
     entering it inherited the judgment, `_owner_keys` being a prefix test.
     Fix: a gitfile must point to a gitdir root (`gitdir_roots`), and
     coverage is those roots ([102]).
[104] The marker expired by the clock (`GITGUARD_JUDGED_TTL`, 60 s), which
     changed the answer mid-command, not its cost: every submodule of a
     `clone --recurse-submodules` longer than a minute, a slow `submodule
     foreach`, `filter-branch`, `rebase --exec` were refused as never
     trusted; a stale marker in an editor's shell kept child semantics for
     ever. Fix: the marker carries the pid of the process that set it and
     is valid while that pid is an ancestor (`/proc` on Linux,
     proc_pidinfo on macOS); dead or outside the chain: no marker. No TTL.
[105] `serving` covered every repository: a trusted `post-receive` of a
     hub that runs `cd site && git pull` entered `site` unjudged, and its
     planted hook ran; a linked worktree planted in a non-bare local
     remote (`receive.denyCurrentBranch = updateInstead`) was read by
     receive-pack's `update-index --refresh`. Fix: the served repository,
     opened as enter_repo opens it (`_local_remote`), is an ordinary `repo`
     marker without a tree.
[106] `git daemon`, `git http-backend` and `git-shell` run `git
     upload-pack <dir>` / `git receive-pack <dir>` — the first word, not
     the dashed name: not passed through, the bare repository refused.
     Fix: `SERVERS`, the same passthrough and marker as `TRANSPORT`.
[107] A clone or init run by a child git (pre-commit's first-use `git init`
     in its cache, git-lfs, a hook's clone) got no `new` marker and no
     auto-trust: its index-pack died, its next use was "never trusted".
     Fix: a child's clone is the user's clone — waited for, marker set,
     auto-trusted — unless the marker already covers the result
     (`submodule add`'s clone into `modules/<x>`, the submodules of `clone
     --recurse-submodules`), which the parent's next command, or the clone's
     own auto-trust, takes as a whole.
[108] A covered child's `push` took the full path under its own key: `push
     --recurse-submodules=on-demand`, `submodule foreach git push` refused
     as never trusted; an alias `push -u && push --tags` refused at the
     second push, the first having written the branch tracking. Fix: a
     covered push or archive child is judged on its destination alone
     (`check_remote_destination`, [62] [70]).
[109] A `/dev/null` token in any config value (`alias.q = !git status
     >/dev/null`, global or local) was taken for a path to watch and
     refused as an unreadable directory — every repository at once,
     `trust` included. Pre-existing. Fix: a device, a FIFO or a socket is
     nothing git runs or reads as a file: ignored by `ConfigScan.add`.
[110] `git clone <path>/.git` without a target: the directory name was
     read as `<path>/` cut of `.git`, an empty name; the `new` marker
     covered the whole cwd and nothing was trusted. Fix: a port of
     git_url_basename (dir.c), parity-tested.
[111] A child with another work tree (`!git --work-tree=<site> checkout -f
     main` in a trusted alias) inherited the judgment by key: a relative
     `core.hooksPath` then named `<site>/.githooks`, which nothing judged —
     [72] for children. Fix: the same gitdir with another root is another
     repository ([102]).
[112] `GITGUARD_REAL_GIT` naming gitguard itself (`<exec-path>/git` after
     the diversion) exec'd gitguard for ever. Fix: refused.
     [101]–[112] found by the fifteenth adversarial pass (five agents,
     2026-10-26), fixed on 2026-10-27.
[113] `init --separate-git-dir=<X>` with X a gitdir the sandbox prepared:
     git reinitialises X and keeps its hooks and config; gitguard looked for
     an existing repository at `<dir>/.git` only and auto-trusted X, whose
     planted pre-commit then ran. Fix: an existing `--separate-git-dir`
     target is pre-existing (no auto-trust).
[114] A stale marker revived by pid reuse: a long-lived process left by
     the editor of `git commit` (an Emacs daemon, `code --wait`, a tmux
     server) keeps GITGUARD_JUDGED; once the pid counter wraps to the
     marker's pid, a git it starts (or a process in between) counts the
     marker as an ancestor's, and inherits the old judgment of a repository
     planted since. Fix: the marker names the pid and its start time; the
     reading process is not its own ancestor.
[115] False positive: `filter-branch` always failed. Its gits run with
     `GIT_DIR=<repo>/.git` from `.git-rewrite/t`, and [111]'s rule judged
     any other root as another repository, never trusted. Fix: [120]'s
     rule — another root is covered when nothing the config names lies in
     its tree.
[116] False positive: pre-commit's first use died inside `git commit`. It
     creates its caches with `init --template=`; gitguard read the empty
     value as a template and withheld auto-trust, and the next `remote add`
     was refused. An empty `--template=` copies no template at all, a
     configured one included. Fix: auto-trusted.
[117] False positive: git ≥ 2.47 runs `maintenance run --auto --detach`,
     which daemonizes; its gc, repack, prune left the command's process
     tree, found the marker dead and judged as the user's commands: in a
     submodule (never trusted under its own key) gc was refused at every
     fetch, recorded, notified; in the judged repository after a hashed
     change, it waited GITGUARD_WAIT. Fix: a child git does not detach
     (`--no-detach`, `gc.autoDetach=false`); the auto-gc runs before the
     command returns.
[118] False positive: `upload-archive--writer <dir>` (started by
     `upload-archive`, which sshd runs from `~`) was judged against its cwd:
     every `archive --remote` failed where `~` is an untrusted repository.
     Fix: a server like the others ([106]).
[119] macOS install: the README's shim recipe had no `git.real` (a GUI
     app's PATH has only Apple's git, which then ran as the real one), a
     shim left stale by `brew upgrade` went unnoticed (`'submodule' is not a
     git command`), and the unwrapped warning printed a Debian command.
     Fix: `gitguard exec-path [<dir>]` builds the shim; `trust` reports a
     stale one; the hint fits the platform.
[120] A child at another root inherited what the parent never hashed:
     `worktree remove ../wt` runs `git status` in the linked worktree, whose
     gitdir the parent hashed but whose tree it did not; with husky's
     layout (`core.hooksPath = .husky/_`, ignored) the sandbox's
     `post-index-change` there ran, then the worktree was deleted, evidence
     included. Pre-existing (master's children are raw). Fix: a child whose
     root is not the judged one is covered only when every path its config
     names in its tree was hashed by the parent, or is the same content at
     the same place in the judged tree; otherwise judged. Values of global
     origin are read there as the parent reads them against a submodule's
     tree: explicit relative paths only ([92]). Not closed with it, a [44]
     member: `worktree add ../wt <sandbox's branch>` — its `reset --hard`
     child starts on an empty tree, then checks the branch's hooks out and
     runs `post-index-change` itself.
[121] The served repository's marker covered every gitdir root under it,
     which nobody hashed: a linked worktree planted in a non-bare remote
     with `receive.denyCurrentBranch = updateInstead` (its own gitdir root,
     or a commondir naming a root planted under `modules/`) ran its
     core.fsmonitor during an ordinary push. [105]'s fix held only for a
     common dir outside the remote. Pre-existing. Fix: the served gitdir
     and common dir, exactly.
[122] Push-to-deploy children (`update-index`, `read-tree`) run in the
     remote's work tree; the served marker has no root and covered them
     whatever their tree: a relative `core.hooksPath` of the remote ran a
     hook the sandbox wrote there. Pre-existing. Fix: [120]'s rule, with
     nothing hashed — the child is judged under the remote's own key.
[123] [95] with a file absent at trust: an include (or a hooks directory)
     the trusted config names but that does not exist is not watched
     (ConfigScan.add records what exists); the command checks it out and
     its child reads it. Accepted with [95]; the next command sees it.
[124] False positives of a re-check tried for [95] (a covered child in the
     judged repository re-hashed the tree-side references and refused a
     change): autostash (`rebase`/`merge`/`pull`) across an incoming hook
     change lost the uncommitted work, rc 0; `bisect run` gave wrong
     verdicts; `submodule add` of a second submodule, `pull
     --recurse-submodules`, `rebase --exec`, `revert`, `stash -k` stopped
     half-way. git does not ignore those children's failure. Reverted;
     the legit tests stay.
     [113]–[124] found by the sixteenth adversarial pass (four agents,
     2026-10-27).
[125] False positive, and a gap: a submodule holding a `.lfsconfig`. Its
     child gits name it in their tree (git-lfs reads it where it runs, the
     submodule during `submodule update`'s smudge), the parent watched the
     root's only: every `git status` of the superproject died "never
     trusted" in the submodule ([120]'s rule), and on master, where the
     child was raw, a `lfs.customtransfer.*.path` the sandbox wrote there
     ran unwatched. Fix: the parent watches each submodule's `.lfsconfig`
     as it does its config ([39]). Found reviewing the diffs of
     [113]–[124], 2026-10-28.
[126] An active submodule entered in-process, no child to judge it. The
     user trusted a repository holding `submodule.active = .` — what `clone
     --recurse-submodules` writes into `.git/config`, so it is hashed and
     trusted, and the activation is_submodule_active needs is free for the
     sandbox. The sandbox plants a repository `vendor/x` (its config's
     core.fsmonitor runs a payload) and commits a tree with a gitlink at
     `vendor/x` and a `.gitmodules` naming it, moving the branch to it:
     objects and refs are volatile, the index and the work tree carry no
     gitlink, so gitguard's structural check (index gitlinks, `.gitmodules`
     on disk) sees nothing and does not refuse. `git grep
     --recurse-submodules s HEAD` reads the gitlink from the tree, finds the
     submodule active, and enters `vendor/x/.git` in-process
     (repo_submodule_init tries `<path>/.git` in the work tree first): its
     core.fsmonitor runs on the index refresh, in the user's command, with
     no child git — the exec-path wrap that would judge `vendor/x` never
     runs. DESIGN-exec-path.md section 6 argued the activation was the
     barrier (`.git/config` hashed); `submodule.active = .` defeats that,
     and the claimed fallback barriers — the index check and "a tree reader
     executes nothing of a gitdir at `<path>/.git`" — hold for every
     in-process reader observed (ls-files, diff/log --submodule, rev-list)
     except `grep --recurse-submodules` with a tree argument, which takes
     the gitlink from the tree and runs the gitdir in-process. `log
     --submodule=diff`, by contrast, enters through a child the wrap judges.
     Found 2026-10-28 while reviewing DESIGN-exec-path.md section 6.
     Accepted limitation (2026-10-28, DESIGN.md "Known limitations"):
     by-name activation stays a hashed config write, refused; `trust` warns
     on a `submodule.active` pathspec and names the way out (`git config
     --unset-all submodule.active`; the per-name keys the same clone wrote
     keep every real submodule active).
"""
from __future__ import annotations

import importlib
import inspect
import pkgutil
from typing import Callable


def collect() -> list[tuple[str, Callable]]:
    """Every attack_* function of the package's modules, sorted."""
    out = []
    for m in pkgutil.iter_modules(__path__):
        mod = importlib.import_module(f"{__name__}.{m.name}")
        for name, fn in inspect.getmembers(mod, inspect.isfunction):
            if name.startswith("attack_") and fn.__module__ == mod.__name__:
                label = (fn.__doc__ or name).strip().splitlines()[0]
                out.append((f"{m.name}:{name[7:]}  {label}", fn))
    return sorted(out, key=lambda t: t[0])
