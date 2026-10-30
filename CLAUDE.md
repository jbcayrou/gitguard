# gitguard

`gitguard.py` is the whole program: one file, Python 3 stdlib only, Linux
and macOS. A guard that refuses to run `git` on a repository whose trusted
files (`.git/config`, hooks, attributes, alternates, nested gitdirs…) have
changed since the user last validated them. Threat: untrusted code in a
sandbox with the repository mounted writes into `.git/`; the next `git` on
the host runs it. gitguard is detection; `safe.bareRepository=explicit` and
a global `core.hooksPath` are the prevention layers it assumes.

**`DESIGN.md` is the design record** (threat model, every check and why,
ruled-out alternatives, the catalogue of 125 bypasses). Read the section named below
before touching the matching code; it is long because every paragraph was
paid for by a bypass.

## Rules that are not up for discussion

- **A fingerprint, never a blocklist.** gitguard hashes everything in the
  gitdir and excludes only what git rewrites (`VOLATILE_*`). On a false
  positive, add to the exclusion list; never go back to an inclusion list,
  never add a "known dangerous keys" list. Two closed lists exist, each
  entry with its proof held to git in the tests: the auto-accept list in
  `branch_tracking_only` (three keys git cannot execute) and
  `PINNED_CONFIG` (`core.fsmonitor=false`, the one key an in-process
  reader executes from a repository nobody judged, [126]; the proof is the
  in-process table of `tests/test_claims.py`).
- **Never run git to learn about a repository.** Discovery, config, gitfile,
  index, todo files: all read by gitguard's own ports of git's readers
  (`find_root`, `parse_git_config`, `index_gitlinks`, `_read_path_file`…).
  `git rev-parse`/`git config` would honour the config being judged.
- **Read every file exactly as git does.** Bytes, git's `isspace`, one
  trailing newline, no `strip()`/`splitlines()`; a line git dies on is
  refused, not reinterpreted. Every reader has a parity test with git as
  the oracle (`tests/test_git_parity.py`) and a byte-variant loop.
- **Fail closed.** Unreadable directory, unparsable config, unknown global
  option, internal error: refuse, git does not run.
- **The state blessed is the state shown.** `save_trust` receives the
  manifest already computed and displayed; never recompute at the `y`.
- **Everything displayed goes through `san()`**; no raw mode, no flag the
  caller must remember.
- **No walk of the work tree**; the index gitlink is the barrier, and a
  repository git enters during a command is judged by the child git that
  enters it: gitguard at the exec path, the install this assumes
  (`DESIGN.md`, "Nested repositories"; `DESIGN-exec-path.md`). Never guess
  from the parent which commands enter.
- **The state directory stays outside the repository.**
- **Exclusions are anchored** to a position under a gitdir root, never to a
  bare name (`_child_root`, paths relative to a root in `VOLATILE_*`).
- **A child inherits only what the parent hashed**: the marker names the
  judged gitdir, common dir, root and label, and covers the gitdir roots
  the walk descends (`gitdir_roots`), never a name or a prefix ([102]
  [103]); at another work tree root, only if what its config names there
  was hashed ([115] [120]); a served repository, exactly ([121] [122]). It
  lives as long as the process that set it, pid and start time
  (`_ancestors`), never a clock ([104] [114]); a child git does not
  detach (`keep_attached`, [117]).
- **A child never refuses what its own command just wrote**: those
  writes are judged at the next command ([124]: a re-check lost
  autostashed work).
- **A directory is watched only for keys git reads it from** (`DIR_KEYS`);
  one that contains the repository, at depth 1 only;
  a file is not watched for keys git reads as data (`DATA_KEYS`).
- Only what every command needs is imported at the top of `gitguard.py`
  (each import is paid by every `git`); trust/restore/pending modules are
  imported where used.
- Example user name in code and tests is `user`; no personal name anywhere
  (`grep` before a commit).

## Commands

```
gitguard                 check; exit 1 if suspect or never trusted
gitguard trust | diff | restore [-y]
gitguard git <args>      check, then exec the real git (symlink `git → gitguard`
                         switches to this mode); clone/init auto-trust; branch
                         tracking auto-accepted; other changes: diff + [y/N] on /dev/tty
gitguard list | forget <repo>… | --missing | prune | retrust
gitguard pending [<repo>… | -a | -c <repo>…]   decisions of terminal-less gits
gitguard exec-path [<dir>]   (re)build an exec path whose git is gitguard (macOS, no root)
```

Environment: `GITGUARD_STATE`, `GITGUARD_REAL_GIT`, `GITGUARD_ALLOW_REBASE_EXEC`,
`GITGUARD_NO_PROMPT`, `GITGUARD_WAIT`, `GITGUARD_NO_NOTIFY`, `GITGUARD_KEEP_FSMONITOR`,
`GITGUARD_DEBUG`,
`GITGUARD_JUDGED` (set by gitguard for the git it runs, read by child gits),
`NO_COLOR`; git's own `GIT_DIR`, `GIT_WORK_TREE`, `GIT_COMMON_DIR`,
`GIT_INDEX_FILE`, `GIT_CEILING_DIRECTORIES`, `GIT_CONFIG_*`, `GIT_TEMPLATE_DIR`
are honoured as git honours them.

## Where things are

| topic | code | DESIGN.md section |
|---|---|---|
| discovery, gitfile, commondir, `core.worktree` | `find_root`, `is_bare_gitdir`, `open_repo`, `_core_worktree` (section "discovery", `pytest -m discovery` after a git upgrade) | What the script checks, 1–2 |
| structural refusals (nested `.git`, index names, todo files, symlinks, perms) | `check_structure`, `check_indexes`, `check_volatile_readers`, `VOLATILE_READERS` | What the script checks, 3 |
| what is hashed in the gitdir | `walk_gitdir`, `_child_root`, `_volatile_*`, `VOLATILE_DIRS`, `VOLATILE_FILES` (paths relative to a gitdir root) | What the fingerprint watches in the gitdir |
| paths the config makes git read | `ConfigScan` (`add`, `consider`, `run`), `config_refs`, `DIR_KEYS`, `DATA_KEYS`, `global_config_files`, `iter_global_config`, `env_config` | What the fingerprint watches outside the gitdir |
| the check pipeline (scan → structure → fingerprint) | `inspect`, `Inspection`, `save_trust` | Organization of gitguard.py |
| config parser | `_Src`, `_parse_value`, `parse_git_config` | same, "Config files parsed" |
| output, colours, `san` | `san`, `Style`, `set_output` | Display and sanitization |
| state files, keys, locking | `save_trust`, `load_manifest`, `update_pending` | Storage |
| exec mode: options, clone/init, prompt, pending | `split_global_options`, `parse_new_repo`, `check_or_die`, `ask_on_tty`, `wait_for_decision` | Auto-trust; Exec-mode shortcuts |
| passthroughs that read no repository | `TRANSPORT`, `main` | Which git runs |
| child gits: the marker (pid + start + judged gitdir/common/root/label), coverage by `gitdir_roots` and `tree_named`, `new`, the served repository, no detach, the exec-path wrap, its check and its macOS shim | `Judged`, `_ancestors`, `_proc_lineage`, `read_judged`, `set_judged`, `NewRepo`, `_served_repository`, `keep_attached`, `check_wrap`, `cmd_exec_path`, `PATH_QUERIES`, `run_git` | Nested repositories; DESIGN-exec-path.md |
| performance | PERF.md | Nested repositories (end) |
| what git writes then reads in one command ([44] [66] [77] [86] [88] [95] [123] [124]); what it reads in-process ([126]) | `Judged.covers`, `_hard_link`, `PINNED_CONFIG`, `pin_config_env`, `_git_maybe_bool` | The command that writes what it then reads |
| accepted limitations [44], [71], [74], [126], out-of-scope cases | — | Known limitations |

## Tests

`python3 -m pytest` (~1300 tests, expected failures: [44], [71], [74], [95], [123], [126], the accepted limitations; ~280 s), before
any change. pytest is not on the system python: `python3 -m venv <scratch>/venv
&& venv/bin/pip install pytest`.

- `tests/attacks/` — the attack corpus, one `attack_*` function per bypass,
  `# [n]` = entry in `tests/attacks/__init__.py`. **A new flaw is a function
  there before the fix**; the fix is done when it goes red → green and
  `test_legit.py` stays green.
- `tests/test_legit.py` — ordinary git must stay silent (false-positive guard).
- `tests/test_git_parity.py` — git as the oracle for every reader; a known
  gap is `xfail(strict=True)`, promoted to `tests/attacks/` once fixed.
- `tests/test_claims.py` — every closed list of claims about git in
  gitguard.py (`GLOBAL_FLAGS`, `NEW_REPO_OPTIONS`, `PATH_QUERIES`, index
  extensions) held to git as the oracle, and the child-process barrier
  (git enters a submodule through a child; the in-process entries and the
  activation they need); a new list gets its test there.
  Its second half holds the lists to `tests/inventory/git-<ver>.txt`,
  git's universe taken from its source by `tests/inventory.py` (gitdir
  names, pathname keys, hooks, global options): every item must be
  classified. **On a git upgrade**: regenerate the snapshot from the
  release's source, diff, classify the new lines (DESIGN.md, "Tests").
- `tests/test_commands.py`, `test_nested.py`, `test_prompt.py` (pty),
  `test_pending.py`, `test_unit.py`.
- The scenarios use `REAL_GIT` (conftest) with a **raw** exec path
  (`gg.git`, `gg.raw_env`); the checks run with a **wrapped** one
  (`gg.env`: `GIT_EXEC_PATH` whose `git` is gitguard), as on a machine
  where the exec path is diverted. On a machine where `git` *is* gitguard,
  the suite still works.

Any new vector or false positive becomes a test first. Replay every
reported bypass and every fix by hand, with byte variants, against the real
git before believing it (`DESIGN.md`, "Adversarial review playbook").

Performance figures live in PERF.md with the script that produced them;
update them when the overhead moves.
