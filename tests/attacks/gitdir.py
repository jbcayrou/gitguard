"""Traps planted directly in .git: hooks, config, attributes, alternates…"""
from __future__ import annotations

from pathlib import Path

from tests.conftest import GG, write_exec


def attack_hook_added(gg: GG, repo: Path, tmp_path: Path) -> None:
    """hook added in .git/hooks"""
    write_exec(repo / ".git/hooks/pre-commit")


def attack_hook_sample_modified(gg: GG, repo: Path, tmp_path: Path) -> None:
    """an existing .sample modified (watched too)"""
    (repo / ".git/hooks/pre-commit.sample").write_text("#!/bin/sh\nid\n")


def attack_config_fsmonitor(gg: GG, repo: Path, tmp_path: Path) -> None:
    """core.fsmonitor in .git/config — run by a plain git status"""
    gg.git("config", "core.fsmonitor", "/tmp/evil", cwd=repo)


def attack_config_alias_shell(gg: GG, repo: Path, tmp_path: Path) -> None:
    """shell alias (!cmd) in .git/config"""
    gg.git("config", "alias.st", "!id", cwd=repo)


def attack_config_pager(gg: GG, repo: Path, tmp_path: Path) -> None:
    """core.pager — any config key counts, not a blocklist"""
    gg.git("config", "core.pager", "/tmp/evil", cwd=repo)


def attack_alternates(gg: GG, repo: Path, tmp_path: Path) -> None:
    """objects/info/alternates → objects read elsewhere"""
    p = repo / ".git/objects/info/alternates"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("/tmp/x\n")


def attack_info_attributes(gg: GG, repo: Path, tmp_path: Path) -> None:
    """info/attributes (filters, diff drivers)"""
    (repo / ".git/info/attributes").write_text("* filter=evil\n")


def attack_unknown_file_anywhere(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[13] unknown file anywhere in .git: watched by default"""
    p = repo / ".git/x/y/z"
    p.parent.mkdir(parents=True)
    p.write_text("x")


def attack_description_modified(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[13] even .git/description is watched (deny-by-default)"""
    (repo / ".git/description").write_text("x\n")


def attack_config_world_writable(gg: GG, repo: Path, tmp_path: Path) -> None:
    """world-writable config"""
    (repo / ".git/config").chmod(0o666)


def attack_hooks_path_inside_gitdir(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[13] core.hooksPath = .git/myhooks (subdirectory not named hooks)"""
    (repo / ".git/myhooks").mkdir()
    gg.git("config", "core.hooksPath", ".git/myhooks", cwd=repo)
    gg.trust(repo)                       # legitimate config trusted by the victim
    write_exec(repo / ".git/myhooks/pre-commit")


def attack_fake_root_marker_in_hooks(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[29] .git/hooks/HEAD: hooks/ passed for a gitdir root, and its HEAD,
    refs/, logs/… became volatile (invisible)"""
    (repo / ".git/hooks/HEAD").write_text("ref: refs/heads/main\n")


def attack_fake_root_marker_hides_subdir(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[29] .git/hooks/HEAD then .git/hooks/refs/x: neither alerted"""
    (repo / ".git/hooks/HEAD").write_text("ref: refs/heads/main\n")
    (repo / ".git/hooks/refs").mkdir()
    write_exec(repo / ".git/hooks/refs/x")
