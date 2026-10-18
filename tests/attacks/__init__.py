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
gitguard.py refer to this list (how the project reviews itself: CLAUDE.md,
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
[51] Modified during git's run, then put back: a sandbox still running
     edits a watched file after the check (a hook while the editor is open,
     during a rebase…) and restores it — every check saw the trusted state.
     Not in the corpus (git runs by design). Detection: a stat snapshot
     before the fingerprint, compared after git exits; ctime cannot be set
     from user space. `.tampered` marker, refusal until trust/restore.
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
