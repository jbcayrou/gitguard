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


def attack_global_gitconfig(gg: GG, repo: Path, tmp_path: Path) -> None:
    """~/.gitconfig modified ($HOME mounted in the container)"""
    gg.git("config", "--global", "core.sshCommand", "/tmp/evil", cwd=repo)


def attack_global_gitconfig_symlink_target(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[22] ~/.gitconfig is a symlink (dotfiles): the target's content changes,
    the link string does not → the global scope fingerprint did not move"""
    import os
    home = Path(gg.env["HOME"])
    dot = tmp_path / "dotfiles" / "gitconfig"
    dot.parent.mkdir()
    (home / ".gitconfig").rename(dot)
    os.symlink(dot, home / ".gitconfig")
    gg.trust(repo)
    dot.write_text(dot.read_text() + "[core]\n\tsshCommand = /tmp/evil\n")


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


def attack_rebase_todo_exec_in_submodule(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[36] `exec` line in a submodule's todo (.git/modules/sub/rebase-merge):
    only the top gitdir was read, `submodule foreach 'git rebase --continue'`
    runs it through an unwrapped git"""
    from tests.attacks._helpers import add_submodule
    sub = add_submodule(gg, repo, tmp_path)
    todo = _interrupted_rebase(gg, sub, tmp_path)
    gg.trust(repo)
    todo.write_text("exec /tmp/evil\n" + todo.read_text())
