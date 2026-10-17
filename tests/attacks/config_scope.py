"""Config files git reads but gitguard might not parse: global config, main
repository config seen from a worktree, deep include chains. [16], [17], [18]
"""
from __future__ import annotations

import getpass
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


def _alias_script(gg: GG, repo: Path, alias: str) -> None:
    write_exec(repo / "tool.sh", "#!/bin/sh\nexit 0\n")
    gg.git("config", "alias.t", alias, cwd=repo)
    gg.trust(repo)
    write_exec(repo / "tool.sh", "#!/bin/sh\ntouch /tmp/evil\n")


def attack_alias_script_via_pwd(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[37] `!$PWD/tool.sh`: a `!` alias runs from the top of the tree, the
    shell expands $PWD there; the token was not recognised as a path"""
    _alias_script(gg, repo, "!$PWD/tool.sh")


def attack_alias_script_via_pwd_braces(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[37] `!sh -c 'exec ${PWD}/tool.sh'`"""
    _alias_script(gg, repo, "!sh -c 'exec ${PWD}/tool.sh'")


def attack_alias_script_via_toplevel(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[37] `!$(git rev-parse --show-toplevel)/tool.sh` (common alias idiom)"""
    _alias_script(gg, repo, "!$(git rev-parse --show-toplevel)/tool.sh")


def attack_alias_script_via_assignment(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[37] `!T=./tool.sh sh -c '$T'`: path on the right of `=`"""
    _alias_script(gg, repo, "!T=./tool.sh sh -c '$T'")


def attack_alias_script_via_home(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[37] `!$HOME/bin/tool.sh`: $HOME is the same for gitguard and the shell"""
    tool = Path(gg.env["HOME"]) / "bin/tool.sh"
    write_exec(tool, "#!/bin/sh\nexit 0\n")
    gg.git("config", "alias.t", "!$HOME/bin/tool.sh", cwd=repo)
    gg.trust(repo)
    write_exec(tool, "#!/bin/sh\ntouch /tmp/evil\n")


def attack_readonly_ext_script(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[38] script outside the tree, mode 0555, in a writable directory:
    `os.access(file, W_OK)` was false so it was ignored, but the container
    can unlink it and recreate it"""
    tool = tmp_path / "vol-tools" / "tool.sh"
    write_exec(tool, "#!/bin/sh\nexit 0\n")
    tool.chmod(0o555)
    gg.git("config", "alias.t", f"!{tool}", cwd=repo)
    gg.trust(repo)
    tool.unlink()
    write_exec(tool, "#!/bin/sh\ntouch /tmp/evil\n")
    tool.chmod(0o555)


def attack_submodule_config_hookspath(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[39] core.hooksPath in .git/modules/sub/config pointing into the
    submodule's tree: that config was hashed but never parsed, so the hooks
    it names were not watched (`submodule foreach 'git commit'` runs them)"""
    from tests.attacks._helpers import add_submodule
    sub = add_submodule(gg, repo, tmp_path)
    write_exec(sub / ".hk/post-commit", "#!/bin/sh\nexit 0\n")
    gg.git("config", "core.hooksPath", ".hk", cwd=sub)
    gg.trust(repo)
    write_exec(sub / ".hk/post-commit", "#!/bin/sh\ntouch /tmp/evil\n")


def attack_submodule_config_alias_script(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[39] `!./tool.sh` alias in a submodule's config: relative to the
    submodule's tree, not the superproject's"""
    from tests.attacks._helpers import add_submodule
    sub = add_submodule(gg, repo, tmp_path)
    write_exec(sub / "tool.sh", "#!/bin/sh\nexit 0\n")
    gg.git("config", "alias.t", "!./tool.sh", cwd=sub)
    gg.trust(repo)
    write_exec(sub / "tool.sh", "#!/bin/sh\ntouch /tmp/evil\n")


def attack_local_remote_hook(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[45] remote.origin.url = a local repository in the volume:
    `git push` runs that repository's pre-receive/update/post-receive hooks
    (and honours its config), none of which is in the fingerprint"""
    sib = tmp_path / "vol-remote.git"
    gg.git("init", "-q", "--bare", str(sib))
    gg.git("remote", "add", "origin", str(sib), cwd=repo)
    gg.trust(repo)
    write_exec(sib / "hooks/pre-receive", "#!/bin/sh\ntouch /tmp/evil\n")


# [46] parser divergences: the user's config carries a core.hooksPath written
# in a form the old parser misread; git honours it, the sandbox rewrites the hook.
def _hooks_in_tree_then_rewritten(gg: GG, repo: Path, config_tail: bytes, hooks: str = ".githooks") -> None:
    write_exec(repo / hooks / "pre-commit", "#!/bin/sh\nexit 0\n")
    cfg = repo / ".git/config"
    cfg.write_bytes(cfg.read_bytes() + config_tail)
    assert gg.git("config", "--get", "core.hookspath", cwd=repo).rc == 0, "git must honour it"
    gg.trust(repo)
    write_exec(repo / hooks / "pre-commit")


def attack_hookspath_after_comment_backslash(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[46] core.hooksPath on the line after a comment ending with `\\`"""
    _hooks_in_tree_then_rewritten(gg, repo, b"[core]\n# husky \\\n\thooksPath = .githooks\n")


def attack_hookspath_after_inline_comment_backslash(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[46] core.hooksPath after a value whose trailing comment ends with `\\`"""
    _hooks_in_tree_then_rewritten(gg, repo, b"[core]\n\tpager = less # x \\\n\thooksPath = .githooks\n")


def attack_hookspath_backslash_at_eof(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[46] core.hooksPath = .githooks\\ at EOF without a newline"""
    _hooks_in_tree_then_rewritten(gg, repo, b"[core]\n\thooksPath = .githooks\\")


def attack_hookspath_under_bom(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[46] config starting with a UTF-8 BOM"""
    write_exec(repo / ".githooks/pre-commit", "#!/bin/sh\nexit 0\n")
    cfg = repo / ".git/config"
    cfg.write_bytes(b"\xef\xbb\xbf[core]\n\thooksPath = .githooks\n" + cfg.read_bytes())
    assert gg.git("config", "--get", "core.hookspath", cwd=repo).rc == 0
    gg.trust(repo)
    write_exec(repo / ".githooks/pre-commit")


def attack_hookspath_internal_whitespace(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[46] hooks directory named `my  hooks` (two spaces): the old parser
    collapsed the value and watched another directory"""
    _hooks_in_tree_then_rewritten(gg, repo, b"[core]\n\thooksPath = my  hooks\n", "my  hooks")


def attack_hookspath_nbsp(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[46] hooks directory whose name ends with a no-break space: str.strip()
    removed it, git keeps it"""
    _hooks_in_tree_then_rewritten(gg, repo, "[core]\n\thooksPath = hooks\u00a0\n".encode(), "hooks\u00a0")


def attack_hookspath_tilde_user(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[50] core.hooksPath = ~<user>/… (git expands it, only ~/ was)"""
    import os
    home = Path(os.path.expanduser(f"~{getpass.getuser()}"))
    # the volume, reached from the user's real home (`~user/../..` when the
    # test directory is not under it): the path git builds is the same
    d = os.path.relpath(tmp_path / "vol-hooks", home)
    write_exec(tmp_path / "vol-hooks/pre-commit", "#!/bin/sh\nexit 0\n")
    gg.git("config", "core.hooksPath", f"~{getpass.getuser()}/{d}", cwd=repo)
    r = gg.git("rev-parse", "--path-format=absolute", "--git-path", "hooks", cwd=repo)
    assert Path(r.out.strip()).resolve() == (tmp_path / "vol-hooks").resolve(), r.text
    gg.trust(repo)
    write_exec(tmp_path / "vol-hooks/pre-commit")


def attack_core_worktree_hooks(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[47] core.worktree = another directory: a relative core.hooksPath
    lives there, not next to .git"""
    other = tmp_path / "other"
    write_exec(other / ".githooks/pre-commit", "#!/bin/sh\nexit 0\n")
    gg.git("config", "core.worktree", str(other), cwd=repo)
    gg.git("config", "core.hooksPath", ".githooks", cwd=repo)
    gg.trust(repo)
    write_exec(other / ".githooks/pre-commit")


def attack_env_config_hookspath(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[48] core.hooksPath set through GIT_CONFIG_COUNT in the user's
    environment, pointing into the tree"""
    gg.env.update(GIT_CONFIG_COUNT="1", GIT_CONFIG_KEY_0="core.hooksPath",
                  GIT_CONFIG_VALUE_0=".githooks")
    write_exec(repo / ".githooks/pre-commit", "#!/bin/sh\nexit 0\n")
    gg.trust(repo)
    write_exec(repo / ".githooks/pre-commit")


def attack_env_config_include(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[48] GIT_CONFIG_PARAMETERS with an absolute include.path into the volume"""
    inc = tmp_path / "vol.gitconfig"
    inc.write_text("[core]\n")
    gg.env["GIT_CONFIG_PARAMETERS"] = f"'include.path'='{inc}'"
    gg.trust(repo)
    inc.write_text("[core]\n\tfsmonitor = /tmp/evil\n")
