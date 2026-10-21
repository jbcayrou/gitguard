"""Attacks against gitguard itself: file names, display, global config. [11], [12]"""
from __future__ import annotations

import shlex
import subprocess
import sys
from pathlib import Path

from tests.conftest import GG, write_exec


def attack_newline_in_filename(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[11] newline in a name: line injection into the manifest"""
    (repo / ".githooks").mkdir()
    gg.git("config", "core.hooksPath", ".githooks", cwd=repo)
    gg.trust(repo)
    (repo / ".githooks" / "x\n644 abc HEAD").write_text("")


def attack_escape_in_filename(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[12] ESC sequence in a hook name: spoofable display"""
    (repo / ".git/hooks" / "pre-commit\x1b[2K").write_text("")


def attack_rebase_todo_exec(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[19] `exec` line injected into .git/rebase-merge/git-rebase-todo"""
    for i in range(3):
        (repo / "f").write_text(f"{i}\n")
        gg.git("add", "f", cwd=repo)
        gg.git("commit", "-qm", f"c{i}", cwd=repo)
    gg.trust(repo)
    # Portable editor: `sed -i '2i break'` is GNU-only (fails with BSD sed).
    editor = tmp_path / "seq-editor.py"
    editor.write_text("import sys\np = sys.argv[1]\nl = open(p).read().split('\\n')\n"
                      "l.insert(1, 'break')\nopen(p, 'w').write('\\n'.join(l))\n")
    env = dict(gg.env, GIT_SEQUENCE_EDITOR=f"{shlex.quote(sys.executable)} {shlex.quote(str(editor))}")
    r = subprocess.run(["git", "rebase", "-i", "HEAD~2"], cwd=repo, env=env,
                       capture_output=True, text=True)
    todo = repo / ".git/rebase-merge/git-rebase-todo"
    assert todo.is_file(), f"interrupted rebase not obtained: {r.stderr}"
    todo.write_text("exec /tmp/evil\n" + todo.read_text())


def _interrupted_rebase(gg: GG, wt: Path, tmp_path: Path) -> Path:
    """Three commits in `wt`, then `rebase -i HEAD~2` stopped on a `break`.
    Returns the todo file (in the gitdir git resolves from `wt`)."""
    for i in range(3):
        (wt / "r").write_text(f"{i}\n")
        gg.git("add", "r", cwd=wt)
        gg.git("commit", "-qm", f"r{i}", cwd=wt)
    editor = tmp_path / "seq-editor.py"
    editor.write_text("import sys\np = sys.argv[1]\nl = open(p).read().split('\\n')\n"
                      "l.insert(1, 'break')\nopen(p, 'w').write('\\n'.join(l))\n")
    env = dict(gg.env, GIT_SEQUENCE_EDITOR=f"{shlex.quote(sys.executable)} {shlex.quote(str(editor))}")
    r = subprocess.run(["git", "rebase", "-i", "HEAD~2"], cwd=wt, env=env,
                       capture_output=True, text=True)
    gd = Path(gg.git("rev-parse", "--absolute-git-dir", cwd=wt).out.strip())
    todo = gd / "rebase-merge/git-rebase-todo"
    assert todo.is_file(), f"interrupted rebase not obtained: {r.stderr}"
    return todo


def attack_rebase_todo_exec_tab(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[35] `exec<TAB>cmd` in the rebase todo: git accepts any blank after the
    command word, check_rebase_todo only split on a space"""
    todo = _interrupted_rebase(gg, repo, tmp_path)
    gg.trust(repo)
    todo.write_text("exec\t/tmp/evil\n" + todo.read_text())


def attack_rebase_strategy_binary(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[51] planted `strategy` in .git/rebase-merge: git execs `git-merge-<name>` on
    `rebase --continue`, bypassing git's own strategy validation"""
    todo = _interrupted_rebase(gg, repo, tmp_path)
    gg.trust(repo)
    (todo.parent / "strategy").write_text("pwned\n")


def attack_rebase_strategy_trailing_blank(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[51] `ort ` in the rebase strategy: git execs `git-merge-ort ` (trailing
    blank kept, only the final newline is trimmed), a strip() saw the builtin"""
    todo = _interrupted_rebase(gg, repo, tmp_path)
    gg.trust(repo)
    (todo.parent / "strategy").write_text("ort\t")


def attack_rebase_strategy_trailing_cr(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[51] `ort<CR>`: a lone CR is not trimmed by git (`git-merge-ort<CR>`),
    but text-mode reading turned it into the newline gitguard trims"""
    todo = _interrupted_rebase(gg, repo, tmp_path)
    gg.trust(repo)
    (todo.parent / "strategy").write_bytes(b"ort\r")


def attack_rebase_strategy_empty(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[51] empty `strategy`: git execs `git-merge-` (PATH lookup), not a
    builtin either — the first fix skipped an empty name as ignored by git"""
    todo = _interrupted_rebase(gg, repo, tmp_path)
    gg.trust(repo)
    (todo.parent / "strategy").write_bytes(b"")


def attack_rebase_strategy_tree_path(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[51] strategy `/x`: git execs `git-merge-/x`, relative to the cwd, i.e. a
    script of the work tree (no PATH access needed)"""
    todo = _interrupted_rebase(gg, repo, tmp_path)
    gg.trust(repo)
    (todo.parent / "strategy").write_text("/x")
    (repo / "git-merge-").mkdir()
    write_exec(repo / "git-merge-" / "x")


def _interrupted_cherry_pick(gg: GG, wt: Path) -> Path:
    """Two commits cherry-picked with `--strategy=recursive`, stopped on a
    conflict in the first. Returns `sequencer/opts`."""
    (wt / "c").write_text("base\n")
    gg.git("add", "c", cwd=wt)
    gg.git("commit", "-qm", "base", cwd=wt)
    gg.git("checkout", "-qb", "side", cwd=wt)
    for i in (1, 2):
        (wt / "c").write_text(f"side{i}\n")
        gg.git("commit", "-qam", f"s{i}", cwd=wt)
    gg.git("checkout", "-q", "-", cwd=wt)
    (wt / "c").write_text("main\n")
    gg.git("commit", "-qam", "m", cwd=wt)
    gg.git("cherry-pick", "--strategy=recursive", "side~1", "side", cwd=wt)
    opts = Path(gg.git("rev-parse", "--absolute-git-dir", cwd=wt).out.strip()) / "sequencer/opts"
    assert opts.is_file(), "interrupted cherry-pick not obtained"
    return opts


def attack_sequencer_opts_strategy(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[51] `strategy = pwned` in .git/sequencer/opts (cherry-pick/revert): git
    execs `git-merge-pwned` on `--continue`"""
    opts = _interrupted_cherry_pick(gg, repo)
    gg.trust(repo)
    opts.write_text("[options]\n\tstrategy = pwned\n")


def attack_sequencer_opts_strategy_lone_cr(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[52] `strategy = ort<CR>x = /y` in sequencer/opts: git keeps the CR inside
    the value and execs `git-merge-ort<CR>x = /y`, a script of the work tree;
    parse_git_config read the file in text mode, saw two lines, `ort` builtin"""
    opts = _interrupted_cherry_pick(gg, repo)
    gg.trust(repo)
    opts.write_bytes(b"[options]\n\tstrategy = ort\rx = /y\n")
    write_exec(repo / "git-merge-ort\rx = " / "y")


def attack_config_hookspath_lone_cr(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[52] trusted `core.hooksPath = .githooks<CR>x = y`: git's hooks directory
    is `.githooks<CR>x = y`, gitguard watched `.githooks`"""
    cfg = repo / ".git/config"
    cfg.write_bytes(cfg.read_bytes() + b"[core]\n\thooksPath = .githooks\rx = y\n")
    (repo / ".githooks").mkdir()
    gg.trust(repo)
    write_exec(repo / ".githooks\rx = y" / "pre-commit")


def attack_rebase_todo_exec_in_submodule(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[36] `exec` line in a submodule's todo (.git/modules/sub/rebase-merge):
    only the top gitdir was read, `submodule foreach 'git rebase --continue'`
    runs it through an unwrapped git"""
    from tests.attacks._helpers import add_submodule
    sub = add_submodule(gg, repo, tmp_path)
    todo = _interrupted_rebase(gg, sub, tmp_path)
    gg.trust(repo)
    todo.write_text("exec /tmp/evil\n" + todo.read_text())
