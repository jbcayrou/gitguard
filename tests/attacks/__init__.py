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
     very command the user runs (checkout/merge/reset of a commit the
     container created, refs and objects being volatile), then executed.
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
[66] OPEN — the gitlink arrives with the command. "The gitlink is the
     barrier" (DESIGN.md, Nested repositories) assumed a gitlink exists in
     the index before the command that opens the nested repository. The
     sandbox plants an untracked repository `vendor/x` (core.fsmonitor),
     a commit whose tree has a gitlink at `vendor/x`, and moves a branch to
     it (objects and refs volatile). `git checkout`/`git switch` to that
     branch writes the gitlink, then shows the local changes, enters
     `vendor/x` and runs its fsmonitor, in the same command; the index
     gitguard read had no gitlink. No special config, no trust-time
     warning: a generalisation of [44]. `checkout -f`, `reset --hard`,
     `merge`, `pull . main` and `checkout -q`
     (no summary of local changes) write the gitlink without entering it. Found by
     an adversarial review, replayed against git 2.50 and 2.47.3. Test:
     test_checkout_brings_a_gitlink_to_a_planted_repository (xfail).
[67] Non-bare local remote with a relative core.hooksPath (husky
     `.husky/_`): receive-pack runs hooks in the remote's $GIT_DIR, so git
     runs `<remote>/.git/.husky/_/<hook>`; gitguard resolved it against
     the remote's work tree. Fix: the remote's relative values resolve
     against its gitdir, where enter_repo chdirs
     (`test_local_remote_relative_hookspath_where_git_resolves_it`: git
     says which hook it runs, every layout).
[68] OPEN — a global (or system) relative core.hooksPath (`.githooks`) was
     resolved against the repository's root only; git applies it in every
     repository it enters: a local bare remote
     (`hub.git/.githooks/pre-receive` on push), a submodule
     (`sub/.githooks/post-checkout` on `submodule update`).
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
     directory, `tools/lint.sh` (what sh runs) is never watched.
[72] OPEN — `--work-tree` without `--git-dir` (or GIT_WORK_TREE alone):
     git discovers the gitdir from the cwd and uses the given tree, where
     it resolves a relative core.hooksPath; gitguard checked the
     discovered tree. ([18] fixed the discovery half.)
[73] remote.pushDefault / branch.<x>.pushRemote / branch.<x>.remote
     naming a path: git pushes to it as a URL; only remote.*.url/pushurl
     were followed, and a bare `git push` has no destination for the [62]
     check. Needs an unusual trusted config. Fix: the three keys are
     followed as local remotes, like remote.*.url.
[74] OPEN — an unset variable glued inside a word (`!sh
     ./tools$NOPE/lint.sh`, `${NOPE}`) expands to nothing in sh; the sh
     readings [58] give `.` or keep the text, never the empty expansion.
     Low realism.
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
