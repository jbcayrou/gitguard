"""Work-tree paths the config makes git execute or read.

The container only needs to write into the tree: hooksPath, includes, alias
scripts. [1], [4], [5], [8]
"""
from __future__ import annotations

from pathlib import Path

from tests.conftest import GG, write_exec


def _hookspath(gg: GG, repo: Path, value: str, where: Path) -> None:
    where.mkdir(parents=True, exist_ok=True)
    write_exec(where / "pre-commit", "#!/bin/sh\nexit 0\n")
    gg.git("config", "core.hooksPath", value, cwd=repo)
    gg.git("add", "-A", cwd=repo)
    gg.git("commit", "-qm", "hooks", cwd=repo)
    gg.trust(repo)


def attack_hookspath_rewritten(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[1] core.hooksPath=.githooks (husky/lefthook): tree hook rewritten"""
    _hookspath(gg, repo, ".githooks", repo / ".githooks")
    write_exec(repo / ".githooks/pre-commit", "#!/bin/sh\necho PWNED\n")


def attack_hookspath_new_file(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[1] new hook dropped into the hooksPath directory"""
    _hookspath(gg, repo, ".githooks", repo / ".githooks")
    write_exec(repo / ".githooks/post-checkout")


def attack_hookspath_absolute(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[1] absolute hooksPath pointing into the tree"""
    _hookspath(gg, repo, str(repo / ".githooks"), repo / ".githooks")
    write_exec(repo / ".githooks/pre-commit")


def attack_hookspath_outside_tree_writable(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[4] hooksPath=../shared-hooks: outside the tree but inside the volume (ext:)"""
    _hookspath(gg, repo, "../shared-hooks", tmp_path / "shared-hooks")
    write_exec(tmp_path / "shared-hooks/pre-commit")


def attack_include_path_in_tree(gg: GG, repo: Path, tmp_path: Path) -> None:
    """include.path to a file in the tree"""
    (repo / ".gitconfig-local").write_text("[core]\n")
    gg.git("config", "include.path", "../.gitconfig-local", cwd=repo)
    gg.trust(repo)
    (repo / ".gitconfig-local").write_text("[core]\n\tfsmonitor = /tmp/evil\n")


def attack_include_chain_level2(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[8] chained include.path: 2nd-level file modified"""
    (repo / "level1").write_text("[include]\n\tpath = level2\n")
    (repo / "level2").write_text("[core]\n")
    gg.git("config", "include.path", "../level1", cwd=repo)
    gg.trust(repo)
    (repo / "level2").write_text("[core]\n\tfsmonitor = /tmp/evil\n")


def attack_alias_dot_slash_script(gg: GG, repo: Path, tmp_path: Path) -> None:
    """alias = !./tool.sh: tree script modified"""
    write_exec(repo / "tool.sh", "#!/bin/sh\nexit 0\n")
    gg.git("config", "alias.t", "!./tool.sh", cwd=repo)
    gg.trust(repo)
    write_exec(repo / "tool.sh")


def attack_alias_relative_no_dot_slash(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[5] alias = !sh tool.sh: relative reference without ./"""
    (repo / "tool.sh").write_text("echo ok\n")
    gg.git("config", "alias.t", "!sh tool.sh", cwd=repo)
    gg.trust(repo)
    (repo / "tool.sh").write_text("echo PWNED\n")


def attack_alias_spaced_path(gg: GG, repo: Path, tmp_path: Path) -> None:
    """alias path containing a space: config_refs lost it (value.split())
    while git executes it through the quotes — analogous to [5]"""
    write_exec(repo / "my tool.sh", "#!/bin/sh\nexit 0\n")
    # Quotes in the value: sh (hence git) treats the spaced path as a single
    # word and executes it. parse_git_config strips the quotes, then
    # config_refs did value.split() → './my' and 'tool.sh', neither exists →
    # the script was never recorded as a watched reference.
    gg.git("config", "alias.t", '!"./my tool.sh"', cwd=repo)
    gg.trust(repo)
    write_exec(repo / "my tool.sh", "#!/bin/sh\necho PWNED\n")


def attack_filter_spaced_path(gg: GG, repo: Path, tmp_path: Path) -> None:
    """same flaw via filter.<f>.clean: spaced script not watched"""
    write_exec(repo / "my clean.sh", "#!/bin/sh\ncat 2>/dev/null; true\n")
    (repo / ".gitattributes").write_text("*.dat filter=x\n")
    gg.git("config", "filter.x.clean", '"./my clean.sh"', cwd=repo)
    gg.git("add", "-A", cwd=repo)
    gg.git("commit", "-qm", "f", cwd=repo)
    gg.trust(repo)
    write_exec(repo / "my clean.sh", "#!/bin/sh\necho PWNED\ncat 2>/dev/null; true\n")


def attack_hookspath_into_volatile_gitdir(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[22] core.hooksPath=.git/logs/h: under a VOLATILE_DIR of the gitdir,
    neither fingerprinted by walk_gitdir nor added as a ref (config_refs.add
    returned early, "covered by the manifest") → hook rewritten after trust
    without alert"""
    d = repo / ".git/logs/h"
    d.mkdir(parents=True)
    write_exec(d / "pre-commit", "#!/bin/sh\nexit 0\n")
    gg.git("config", "core.hooksPath", ".git/logs/h", cwd=repo)
    gg.run("trust", cwd=repo)           # refusal at trust time is accepted (volatile zone)
    write_exec(d / "pre-commit")
