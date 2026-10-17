"""Config files git reads but gitguard might not parse: global config, main
repository config seen from a worktree, deep include chains. [16], [17], [18]
"""
from __future__ import annotations

from pathlib import Path

from tests.conftest import GG, write_exec


def attack_global_hookspath(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[16] core.hooksPath in ~/.gitconfig pointing into the volume"""
    shared = tmp_path / "vol-hooks"
    write_exec(shared / "pre-commit", "#!/bin/sh\nexit 0\n")
    gg.git("config", "--global", "core.hooksPath", str(shared))
    gg.trust(repo)
    write_exec(shared / "pre-commit")


def attack_global_include_path(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[16] include.path in ~/.gitconfig to a file in the volume"""
    inc = tmp_path / "shared.gitconfig"
    inc.write_text("[core]\n")
    gg.git("config", "--global", "include.path", str(inc))
    gg.trust(repo)
    inc.write_text("[core]\n\tfsmonitor = /tmp/evil\n")


def attack_include_chain_depth7(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[17] include chain of depth 7 (git follows 10)"""
    for i in range(1, 7):
        (repo / f"l{i}").write_text(f"[include]\n\tpath = l{i + 1}\n")
    (repo / "l7").write_text("[core]\n")
    gg.git("config", "include.path", "../l1", cwd=repo)
    gg.trust(repo)
    (repo / "l7").write_text("[core]\n\tfsmonitor = /tmp/evil\n")


def attack_inline_section_hookspath(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[21] `[core]hooksPath = .githooks` on a single line: git reads the key,
    parse_git_config dropped it with the header → .githooks never watched"""
    write_exec(repo / ".githooks/pre-commit", "#!/bin/sh\nexit 0\n")
    cfg = repo / ".git/config"
    cfg.write_text(cfg.read_text() + "[core]hooksPath = .githooks\n")
    gg.trust(repo)
    write_exec(repo / ".githooks/pre-commit", "#!/bin/sh\ntouch /tmp/evil\n")


def attack_inline_section_include_path(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[21] `[include]path = ../inc.cfg` on one line: include never followed
    (path relative to the config file's directory, i.e. `.git/`)"""
    (repo / "inc.cfg").write_text("[core]\n")
    cfg = repo / ".git/config"
    cfg.write_text(cfg.read_text() + "[include]path = ../inc.cfg\n")
    gg.trust(repo)
    (repo / "inc.cfg").write_text("[core]\n\tfsmonitor = /tmp/evil\n")


def attack_inline_section_alias(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[21] `[alias]t = !./tool.sh` on one line: tree script not watched"""
    write_exec(repo / "tool.sh", "#!/bin/sh\nexit 0\n")
    cfg = repo / ".git/config"
    cfg.write_text(cfg.read_text() + "[alias]t = !./tool.sh\n")
    gg.trust(repo)
    write_exec(repo / "tool.sh", "#!/bin/sh\ntouch /tmp/evil\n")


def attack_include_into_volatile_gitdir(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[22] include.path=logs/x.conf: included config under logs/ (volatile),
    not fingerprinted → execution key added after trust without alert"""
    inc = repo / ".git/logs/x.conf"
    inc.parent.mkdir(parents=True, exist_ok=True)
    inc.write_text("[core]\n")
    gg.git("config", "include.path", "logs/x.conf", cwd=repo)
    gg.run("trust", cwd=repo)           # refusal at trust time is accepted (volatile zone)
    inc.write_text("[core]\n\tfsmonitor = /tmp/evil\n")


def attack_include_chain_depth10_script(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[17] include.path depth 10: git reads the 10th file (MAX_INCLUDE_DEPTH)
    but config_refs only parsed 9 levels (the first loop round consumed the
    base files) → the script referenced at the 10th level escaped watching"""
    write_exec(repo / "scanner.sh", "#!/bin/sh\nexit 1\n")
    for i in range(1, 10):
        (repo / f"l{i}").write_text(f"[include]\n\tpath = l{i + 1}\n")
    (repo / "l10").write_text("[core]\n\tfsmonitor = ./scanner.sh\n")
    gg.git("config", "include.path", "../l1", cwd=repo)
    gg.trust(repo)
    write_exec(repo / "scanner.sh", "#!/bin/sh\necho PWNED\nexit 1\n")
