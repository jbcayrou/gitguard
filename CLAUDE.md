# gitguard

`gitguard.py` is the whole program: one file, Python 3 stdlib only, Linux
and macOS. A guard that refuses to run `git` on a repository whose trusted
files (`.git/config`, hooks, attributes, alternates, nested gitdirs…) have
changed since the user last validated them. Threat: untrusted code in a
sandbox with the repository mounted writes into `.git/`; the next `git` on
the host runs it. gitguard is detection; `safe.bareRepository=explicit` and
a global `core.hooksPath` are the prevention layers it assumes.

**`DESIGN.md` is the design record** (threat model, every check and why,
ruled-out alternatives, the catalogue of 99 bypasses). Read the section named below
before touching the matching code; it is long because every paragraph was
paid for by a bypass.

## Rules that are not up for discussion

- **A fingerprint, never a blocklist.** gitguard hashes everything in the
  gitdir and excludes only what git rewrites (`VOLATILE_*`). On a false
  positive, add to the exclusion list; never go back to an inclusion list,
  never add a "known dangerous keys" list. The auto-accept list in
  `branch_tracking_only` is the one closed allowlist: three keys, each with
  a proof that git cannot execute it.
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
- **No walk of the work tree**; the index gitlink is the barrier
  (`DESIGN.md`, "Nested repositories").
- **The state directory stays outside the repository.**
- **Exclusions are anchored** to a position under a gitdir root, never to a
  bare name (`_child_root`, paths relative to a root in `VOLATILE_*`).
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
```

Environment: `GITGUARD_STATE`, `GITGUARD_REAL_GIT`, `GITGUARD_ALLOW_REBASE_EXEC`,
`GITGUARD_NO_PROMPT`, `GITGUARD_WAIT`, `GITGUARD_NO_NOTIFY`, `GITGUARD_DEBUG`,
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
| the gitlink brought by the command (the switch on every command, the exemption, aliases) | `SWITCH_EXEMPT`, `CmdConfig`, `exempt_from_switch`, `_alias_parts`, `with_ignored_submodule_dirt` | Nested repositories |
| performance | PERF.md | Nested repositories (end) |
| what git writes then reads in one command ([44] [66] [77] [86] [88] [95]) | `SWITCH_EXEMPT`, `_hard_link` | The command that writes what it then reads |
| accepted limitations [44], [71], [74], out-of-scope cases | — | Known limitations |

## Tests

`python3 -m pytest` (~1060 tests, expected failures: [44], [71], [74], the accepted limitations, and the open [89], [95]; ~180 s), before
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
  gitguard.py (`GLOBAL_FLAGS`, `SWITCH_EXEMPT`, `NEW_REPO_OPTIONS`, index
  extensions) held to git as the oracle; a new list gets its test there.
  Its second half holds the lists to `tests/inventory/git-<ver>.txt`,
  git's universe taken from its source by `tests/inventory.py` (gitdir
  names, pathname keys, hooks, global options): every item must be
  classified. **On a git upgrade**: regenerate the snapshot from the
  release's source, diff, classify the new lines (DESIGN.md, "Tests").
- `tests/test_commands.py`, `test_nested.py`, `test_prompt.py` (pty),
  `test_pending.py`, `test_unit.py`.
- The scenarios use `REAL_GIT` (conftest): on a machine where `git` *is*
  gitguard, the suite still works.

Any new vector or false positive becomes a test first. Replay every
reported bypass and every fix by hand, with byte variants, against the real
git before believing it (`DESIGN.md`, "Adversarial review playbook").

Performance figures live in PERF.md with the script that produced them;
update them when the overhead moves.
