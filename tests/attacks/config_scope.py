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


# [58] sh expansions that os.path.expandvars does not perform: the value
# names no existing file for gitguard, sh resolves it to a tree script.
def _fsmonitor_script(gg: GG, repo: Path, value: str) -> None:
    write_exec(repo / "p.sh", "#!/bin/sh\nexit 0\n")
    gg.git("config", "core.fsmonitor", value, cwd=repo)
    gg.trust(repo)
    write_exec(repo / "p.sh", "#!/bin/sh\ntouch /tmp/evil\n")


def attack_fsmonitor_script_via_pwd(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[37] control for [58]: `core.fsmonitor = $PWD/p.sh` (`git status` runs it)"""
    _fsmonitor_script(gg, repo, "$PWD/p.sh")


def attack_fsmonitor_script_via_default_expansion(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[58] `core.fsmonitor = ${TOOL:-./p.sh}`: sh substitutes the default,
    expandvars leaves the text as is"""
    _fsmonitor_script(gg, repo, "${TOOL:-./p.sh}")


def attack_fsmonitor_script_via_subshell_pwd(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[58] `core.fsmonitor = $(pwd)/p.sh`: no variable involved, resolves on
    any machine"""
    _fsmonitor_script(gg, repo, "$(pwd)/p.sh")


def attack_fsmonitor_script_via_backtick_pwd(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[58] core.fsmonitor = `pwd`/p.sh"""
    _fsmonitor_script(gg, repo, "`pwd`/p.sh")


def attack_alias_script_via_default_expansion(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[58] `!${X:-./tool.sh}`"""
    _alias_script(gg, repo, "!${X:-./tool.sh}")


def attack_alias_script_with_alternate_suffix(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[58] `!./tool.sh${OPT:+ x}`: the path is glued to the expansion"""
    _alias_script(gg, repo, "!./tool.sh${OPT:+ x}")


def attack_env_config_fsmonitor_default_expansion(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[58] GIT_CONFIG_PARAMETERS `core.fsmonitor=${X:-./p.sh}` in the user's
    environment: nothing in .git names the script"""
    write_exec(repo / "p.sh", "#!/bin/sh\nexit 0\n")
    gg.env["GIT_CONFIG_PARAMETERS"] = "'core.fsmonitor=${X:-./p.sh}'"
    gg.trust(repo)
    write_exec(repo / "p.sh", "#!/bin/sh\ntouch /tmp/evil\n")


# [59] core.hooksPath resolving to the root of the tree: add() drops a path
# equal to the root, and no walk of the tree covers its top level.
def _hooks_at_root(gg: GG, repo: Path, value: str) -> None:
    write_exec(repo / "pre-commit", "#!/bin/sh\nexit 0\n")
    gg.git("config", "core.hooksPath", value, cwd=repo)
    gg.run("trust", cwd=repo)           # refused at trust time: the expected outcome
    write_exec(repo / "pre-commit", "#!/bin/sh\ntouch /tmp/evil\n")


def attack_hookspath_root_absolute(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[59] `git config core.hooksPath "$(git rev-parse --show-toplevel)"`"""
    _hooks_at_root(gg, repo, str(repo))


def attack_hookspath_root_via_gitdir_parent(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[59] core.hooksPath = .git/.."""
    _hooks_at_root(gg, repo, ".git/..")


def attack_hookspath_root_dot_slash_dot(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[59] core.hooksPath = ./. (`.` and `./` alone make git search the
    PATH for `pre-commit`: nothing of the tree runs)"""
    _hooks_at_root(gg, repo, "./.")


# [61] a local remote [45] redirected the way git redirects any gitdir:
# `commondir`, a gitfile, `config.worktree`. _local_remote watched only
# `<remote>/.git/config` and `hooks/`, not the files git actually opens.
def attack_local_remote_commondir(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[61] `commondir` planted in the local remote's gitdir: receive-pack
    takes config and hooks/ from the directory it names"""
    sib = tmp_path / "vol-remote.git"
    gg.git("init", "-q", "--bare", str(sib))
    gg.git("remote", "add", "origin", str(sib), cwd=repo)
    gg.trust(repo)
    evil = tmp_path / "vol-evil.git"
    gg.git("init", "-q", "--bare", str(evil))
    write_exec(evil / "hooks/pre-receive", "#!/bin/sh\ntouch /tmp/evil\n")
    (sib / "commondir").write_text(f"{evil}\n")


def attack_local_remote_gitfile(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[61] local remote whose `.git` is a gitfile (`init --separate-git-dir`),
    trusted as such: _local_remote did not recognise it, nothing was watched"""
    other, gd = tmp_path / "vol-other", tmp_path / "vol-other-gitdir"
    gg.git("init", "-q", "--separate-git-dir", str(gd), str(other))
    gg.git("remote", "add", "origin", str(other), cwd=repo)
    gg.trust(repo)
    write_exec(gd / "hooks/pre-receive", "#!/bin/sh\ntouch /tmp/evil\n")


def attack_local_remote_worktree_config(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[61] local remote with extensions.worktreeConfig: its config.worktree
    (read by receive-pack) was not watched"""
    sib = tmp_path / "vol-remote.git"
    gg.git("init", "-q", "--bare", str(sib))
    gg.git("config", "extensions.worktreeConfig", "true", cwd=sib)
    gg.git("remote", "add", "origin", str(sib), cwd=repo)
    gg.trust(repo)
    write_exec(tmp_path / "vol-h/pre-receive", "#!/bin/sh\ntouch /tmp/evil\n")
    (sib / "config.worktree").write_text(f"[core]\n\thooksPath = {tmp_path / 'vol-h'}\n")


def attack_hookspath_sourced_lib_rewritten(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[65] control: a hooks directory inside the tree stays watched at any
    depth — `.githooks/pre-commit` sources `.githooks/lib/common.sh`, the
    sandbox rewrites the library (the first depth-1 fix let it run)"""
    write_exec(repo / ".githooks/pre-commit", '#!/bin/sh\n. "$(dirname "$0")/lib/common.sh"\n')
    (repo / ".githooks/lib").mkdir()
    (repo / ".githooks/lib/common.sh").write_text("true\n")
    gg.git("config", "core.hooksPath", ".githooks", cwd=repo)
    gg.trust(repo)
    (repo / ".githooks/lib/common.sh").write_text("touch /tmp/evil\n")


def attack_hookspath_parent_hook_planted(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[65] control: core.hooksPath = .. is watched at depth 1 — a hook
    planted next to the repository is seen (git runs `../pre-commit`)"""
    gg.git("config", "core.hooksPath", "..", cwd=repo)
    gg.trust(repo)
    write_exec(tmp_path / "pre-commit", "#!/bin/sh\ntouch /tmp/evil\n")


def attack_template_dir_hook_rewritten(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[65] control: init.templateDir keeps its hooks/ watched once walks
    stop at depth 1 (a re-run `git init` copies them into .git/hooks)"""
    tpl = tmp_path / "vol-tpl"
    write_exec(tpl / "hooks/post-checkout", "#!/bin/sh\nexit 0\n")
    gg.git("config", "init.templateDir", str(tpl), cwd=repo)
    gg.trust(repo)
    write_exec(tpl / "hooks/post-checkout", "#!/bin/sh\ntouch /tmp/evil\n")


# ---------------------------------------- adversarial review of 2026-10-22
def attack_local_remote_relative_hookspath(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[67] non-bare local remote with a relative core.hooksPath
    (husky `.husky/_`): receive-pack runs hooks in the remote's $GIT_DIR,
    git runs `<remote>/.git/.husky/_/pre-receive`; gitguard watched
    `<remote>/.husky/_`"""
    hub = tmp_path / "vol-hub"
    gg.git("init", "-q", str(hub))
    (hub / ".husky/_").mkdir(parents=True)
    gg.git("config", "core.hooksPath", ".husky/_", cwd=hub)
    gg.git("remote", "add", "hub", str(hub), cwd=repo)
    gg.trust(repo)
    write_exec(hub / ".git/.husky/_/pre-receive", "#!/bin/sh\ntouch /tmp/evil\n")


def attack_global_relative_hookspath_in_bare_remote(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[68] a global relative core.hooksPath (`.githooks`) applies to a
    local bare remote too: receive-pack runs `hub.git/.githooks/pre-receive`;
    gitguard resolved the global value against the repository's root only"""
    hub = tmp_path / "vol-hub.git"
    gg.git("init", "-q", "--bare", str(hub))
    gg.git("config", "--global", "core.hooksPath", ".githooks")
    gg.git("remote", "add", "hub", str(hub), cwd=repo)
    gg.trust(repo)
    write_exec(hub / ".githooks/pre-receive", "#!/bin/sh\ntouch /tmp/evil\n")


def attack_global_relative_hookspath_in_submodule(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[68] the same global `.githooks` inside a submodule: `git
    submodule update` checks the submodule out and runs
    `sub/.githooks/post-checkout`"""
    from tests.attacks._helpers import add_submodule
    gg.git("config", "--global", "core.hooksPath", ".githooks")
    sub = add_submodule(gg, repo, tmp_path)
    gg.trust(repo)
    write_exec(sub / ".githooks/post-checkout", "#!/bin/sh\ntouch /tmp/evil\n")


def attack_local_remote_percent_encoded_file_url(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[69] `file://…/My%20Repos/hub.git`: git URL-decodes it and runs
    the remote's hooks on push; _local_remote took the encoded text as a path
    and found no repository"""
    hub = tmp_path / "My Repos/hub.git"
    gg.git("init", "-q", "--bare", str(hub))
    gg.git("remote", "add", "hub", "file://" + str(hub).replace(" ", "%20"), cwd=repo)
    gg.trust(repo)
    write_exec(hub / "hooks/pre-receive", "#!/bin/sh\ntouch /tmp/evil\n")


def attack_alias_script_after_cd(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[71] OPEN — `!cd tools && ./lint.sh`: the token resolves to
    `<root>/lint.sh`, `tools/lint.sh` (what sh runs) is never watched"""
    write_exec(repo / "tools/lint.sh", "#!/bin/sh\nexit 0\n")
    gg.git("config", "alias.lint", "!cd tools && ./lint.sh", cwd=repo)
    gg.trust(repo)
    write_exec(repo / "tools/lint.sh", "#!/bin/sh\ntouch /tmp/evil\n")


def attack_alias_script_in_subshell_after_cd(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[71] OPEN — `!(cd tools; sh lint.sh)`"""
    write_exec(repo / "tools/lint.sh", "#!/bin/sh\nexit 0\n")
    gg.git("config", "alias.lint", "!(cd tools; sh lint.sh)", cwd=repo)
    gg.trust(repo)
    write_exec(repo / "tools/lint.sh", "#!/bin/sh\ntouch /tmp/evil\n")


def attack_push_default_names_a_path(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[73] remote.pushDefault = a path: git takes an unconfigured
    remote name as a URL and pushes there; only remote.*.url/pushurl were
    followed"""
    hub = tmp_path / "vol-hub.git"
    gg.git("init", "-q", "--bare", str(hub))
    gg.git("config", "remote.pushDefault", str(hub), cwd=repo)
    gg.trust(repo)
    write_exec(hub / "hooks/pre-receive", "#!/bin/sh\ntouch /tmp/evil\n")


def attack_push_remote_names_a_path(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[73] branch.main.pushRemote = a path"""
    hub = tmp_path / "vol-hub.git"
    gg.git("init", "-q", "--bare", str(hub))
    gg.git("config", "branch.main.pushRemote", str(hub), cwd=repo)
    gg.trust(repo)
    write_exec(hub / "hooks/pre-receive", "#!/bin/sh\ntouch /tmp/evil\n")


def attack_branch_remote_names_a_path(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[73] branch.main.remote = a path (with an upstream, `git push` goes
    there)"""
    hub = tmp_path / "vol-hub.git"
    gg.git("init", "-q", "--bare", str(hub))
    gg.git("config", "branch.main.remote", str(hub), cwd=repo)
    gg.git("config", "branch.main.merge", "refs/heads/main", cwd=repo)
    gg.trust(repo)
    write_exec(hub / "hooks/pre-receive", "#!/bin/sh\ntouch /tmp/evil\n")


def _program_link(gg: GG, tmp_path: Path, chain: bool = False) -> tuple[Path, Path]:
    """gpg.program named through a symlink outside the tree, as Homebrew
    does; with `chain`, through two links. Returns (link to repoint, target)."""
    real = tmp_path / "vol-bin/Cellar/gpg"
    write_exec(real, "#!/bin/sh\nexit 0\n")
    hop = tmp_path / "vol-bin/hop"
    hop.symlink_to(real)
    link = tmp_path / "vol-bin/gpg"
    link.symlink_to(hop if chain else real)
    gg.git("config", "--global", "gpg.program", str(link))
    return (hop if chain else link), real


def attack_global_program_symlink_repointed(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[75] control: the program link outside the tree is watched as a link:
    repointed to a planted script, seen (the canonical path alone kept
    hashing the old target)"""
    link, _ = _program_link(gg, tmp_path)
    gg.trust(repo)
    write_exec(tmp_path / "vol-bin/evil", "#!/bin/sh\ntouch /tmp/evil\n")
    link.unlink()
    link.symlink_to(tmp_path / "vol-bin/evil")


def attack_global_program_symlink_intermediate_repointed(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[75] control: an unwatched link between the named link and the
    program, repointed: the named link's hash holds the content it reaches"""
    hop, _ = _program_link(gg, tmp_path, chain=True)
    gg.trust(repo)
    write_exec(tmp_path / "vol-bin/evil", "#!/bin/sh\ntouch /tmp/evil\n")
    hop.unlink()
    hop.symlink_to(tmp_path / "vol-bin/evil")


def attack_global_program_symlink_target_rewritten(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[75] control: the program behind the link rewritten"""
    _, real = _program_link(gg, tmp_path)
    gg.trust(repo)
    write_exec(real, "#!/bin/sh\ntouch /tmp/evil\n")


def attack_alias_script_glued_to_empty_variable(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[74] OPEN — `!sh ./tools$NOPE/lint.sh`: an unset variable inside a
    word expands to nothing in sh; the sh readings give `.` or keep the
    text, never the empty expansion"""
    (repo / "tools").mkdir()
    (repo / "tools/lint.sh").write_text("exit 0\n")
    gg.git("config", "alias.lint", "!sh ./tools$NOPE/lint.sh", cwd=repo)
    gg.trust(repo)
    (repo / "tools/lint.sh").write_text("touch /tmp/evil\n")


def attack_alias_config_hookspath(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[80] alias.ci = -c core.hooksPath=.githooks commit: the alias's `-c`
    makes `.githooks` the hooks directory of every `git ci`"""
    write_exec(repo / ".githooks/pre-commit", "#!/bin/sh\nexit 0\n")
    gg.git("config", "alias.ci", "-c core.hooksPath=.githooks commit", cwd=repo)
    gg.trust(repo)
    write_exec(repo / ".githooks/pre-commit", "#!/bin/sh\ntouch /tmp/evil\n")


def attack_global_alias_config_hookspath_quoted(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[80] the same from ~/.gitconfig, quoted and after `-p`"""
    write_exec(repo / ".githooks/pre-push", "#!/bin/sh\nexit 0\n")
    gg.git("config", "--global", "alias.pp", "-p -c 'core.hooksPath=.githooks' push", cwd=repo)
    gg.trust(repo)
    write_exec(repo / ".githooks/pre-push", "#!/bin/sh\ntouch /tmp/evil\n")


def attack_alias_config_hookspath_outside(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[80] an alias's `-c core.hooksPath` naming a directory of the volume"""
    shared = tmp_path / "vol-hooks"
    write_exec(shared / "pre-commit", "#!/bin/sh\nexit 0\n")
    gg.git("config", "alias.ci", f"-c core.hooksPath={shared} commit", cwd=repo)
    gg.trust(repo)
    write_exec(shared / "pre-commit", "#!/bin/sh\ntouch /tmp/evil\n")


def attack_lfsconfig_added(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[34] `.lfsconfig` planted in the tree: git-lfs reads
    lfs.customtransfer.<x>.path from it, a program it runs"""
    write_exec(repo / "t.sh", "#!/bin/sh\ntouch /tmp/evil\n")
    (repo / ".lfsconfig").write_text('[lfs "customtransfer.x"]\n\tpath = ./t.sh\n')


def attack_lfsconfig_rewritten(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[34] a trusted `.lfsconfig` rewritten to name a transfer program"""
    (repo / ".lfsconfig").write_text("[lfs]\n\turl = https://lfs.example/x\n")
    gg.trust(repo)
    write_exec(repo / "t.sh", "#!/bin/sh\ntouch /tmp/evil\n")
    (repo / ".lfsconfig").write_text('[lfs "customtransfer.x"]\n\tpath = ./t.sh\n')


# ------------------------------------------- adversarial review of 2026-10-24 (2)
OK_HOOK = "#!/bin/sh\nexit 0\n"


def _evil(tmp_path: Path) -> str:
    return f"#!/bin/sh\ntouch '{tmp_path}/RAN'\n"


def attack_alias_subsection_config_hookspath(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[90] `[alias "ci"] command = -c core.hooksPath=.githooks commit`
    (git 2.54): the subsection form of the alias of [80], parsed as section
    `alias.ci`, key `command`, never read as an alias"""
    write_exec(repo / ".githooks/pre-commit", OK_HOOK)
    assert gg.git("config", "alias.ci.command", "-c core.hooksPath=.githooks commit", cwd=repo).rc == 0
    gg.trust(repo)
    write_exec(repo / ".githooks/pre-commit", _evil(tmp_path))


def attack_optional_hookspath_local(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[91] `core.hooksPath = :(optional).githooks` (git 2.52+): git
    strips the prefix and runs `.githooks/<hook>`; gitguard watched
    `<root>/:(optional).githooks`, which does not exist"""
    write_exec(repo / ".githooks/post-checkout", OK_HOOK)
    assert gg.git("config", "core.hooksPath", ":(optional).githooks", cwd=repo).rc == 0
    gg.trust(repo)
    write_exec(repo / ".githooks/post-checkout", _evil(tmp_path))


def attack_optional_hookspath_global(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[91] the same from ~/.gitconfig, the use case of `:(optional)`:
    "the repository's .githooks when there is one\""""
    write_exec(repo / ".githooks/post-checkout", OK_HOOK)
    assert gg.git("config", "--global", "core.hooksPath", ":(optional).githooks").rc == 0
    gg.trust(repo)
    write_exec(repo / ".githooks/post-checkout", _evil(tmp_path))


def attack_global_config_hook_relative_in_submodule(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[92] a global config hook with a relative command
    (`hook.conv.command = ./scripts/pc.sh`, git 2.54) runs in every
    repository git enters: `git submodule update` runs `sub/scripts/pc.sh`.
    The [68] re-resolution against each base covers DIR_KEYS only"""
    from tests.attacks._helpers import add_submodule, submodule_source_with
    submodule_source_with(gg, tmp_path, {"scripts/pc.sh": OK_HOOK})
    assert gg.git("config", "--global", "hook.conv.command", "./scripts/pc.sh").rc == 0
    assert gg.git("config", "--global", "hook.conv.event", "post-checkout").rc == 0
    sub = add_submodule(gg, repo, tmp_path)
    gg.trust(repo)
    write_exec(sub / "scripts/pc.sh", _evil(tmp_path))


def attack_shared_include_in_superproject_and_submodule(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[93] one file (`~/team.gitconfig`: core.hooksPath = .githooks)
    included by the superproject's config and by the submodule's: parsed
    once (`seen` keyed by path, not by base), its relative hooksPath
    resolved against the root only; git applies it in `sub/` too"""
    from tests.attacks._helpers import add_submodule, submodule_source_with
    team = Path(gg.env["HOME"]) / "team.gitconfig"
    team.write_text("[core]\n\thooksPath = .githooks\n")
    submodule_source_with(gg, tmp_path, {".githooks/post-checkout": OK_HOOK})
    sub = add_submodule(gg, repo, tmp_path)
    assert gg.git("config", "include.path", "~/team.gitconfig", cwd=sub).rc == 0
    assert gg.git("config", "include.path", "~/team.gitconfig", cwd=repo).rc == 0
    gg.trust(repo)
    write_exec(sub / ".githooks/post-checkout", _evil(tmp_path))


def attack_relative_include_inside_symlinked_include(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[94] a relative `include.path = local.inc` inside an included
    file that is a symlink (`shared/team.inc -> real/team.inc`): git resolves
    it against the directory of the file as opened (`shared/local.inc`),
    gitguard against the target's (`shared/real/local.inc`)"""
    import os
    shared = tmp_path / "vol-shared"
    (shared / "real").mkdir(parents=True)
    (shared / "real/team.inc").write_text("[include]\n\tpath = local.inc\n")
    os.symlink("real/team.inc", shared / "team.inc")
    assert gg.git("config", "include.path", str(shared / "team.inc"), cwd=repo).rc == 0
    gg.trust(repo)
    write_exec(shared / "pwn.sh", _evil(tmp_path) + "exit 1\n")
    (shared / "local.inc").write_text(f"[core]\n\tfsmonitor = {shared / 'pwn.sh'}\n")


def attack_ssh_config_glued_to_short_option(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[96] `core.sshCommand = ssh -F./deploy/ssh_config`: the path
    glued to a short option is one token starting with `-`, dropped; ssh
    reads the file, a ProxyCommand planted there runs on `git fetch`"""
    (repo / "deploy").mkdir()
    (repo / "deploy/ssh_config").write_text("Host *\n\tBatchMode yes\n")
    assert gg.git("config", "core.sshCommand", "ssh -F./deploy/ssh_config", cwd=repo).rc == 0
    assert gg.git("remote", "add", "origin", "ssh://deploy.invalid/r.git", cwd=repo).rc == 0
    gg.trust(repo)
    (repo / "deploy/ssh_config").write_text(
        f"Host *\n\tProxyCommand sh -c \"touch '{tmp_path}/RAN'; exit 1\"\n")


def attack_ssh_config_glued_in_option_cluster(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[96] the same in a cluster, `ssh -vF./deploy/ssh_config` (`-v`, then
    `-F` holding the rest of the word): found replaying the first fix, which
    only took what follows `-F`"""
    (repo / "deploy").mkdir()
    (repo / "deploy/ssh_config").write_text("Host *\n\tBatchMode yes\n")
    assert gg.git("config", "core.sshCommand", "ssh -vF./deploy/ssh_config", cwd=repo).rc == 0
    assert gg.git("remote", "add", "origin", "ssh://deploy.invalid/r.git", cwd=repo).rc == 0
    gg.trust(repo)
    (repo / "deploy/ssh_config").write_text(
        f"Host *\n\tProxyCommand sh -c \"touch '{tmp_path}/RAN'; exit 1\"\n")
