"""Nested .git, fake submodules, redirected gitfiles. [6], [7], [9]"""
from __future__ import annotations

import hashlib
import shutil
from pathlib import Path

from tests.attacks._helpers import add_submodule
from tests.conftest import GG


def attack_nested_git_undeclared(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[14] undeclared nested repository: RCE as soon as a gitlink exists
    (proof: tests/nested_git_is_a_threat.sh)"""
    sub = repo / "vendor"
    sub.mkdir()
    gg.git("init", "-q", cwd=sub)
    (sub / "v").write_text("v\n")
    gg.git("add", "v", cwd=sub)
    gg.git("commit", "-qm", "v", cwd=sub)
    gg.git("config", "core.fsmonitor", "/tmp/evil", cwd=sub)


def attack_nested_git_in_pruned_dir_with_gitlink(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[14] nested repository in a pruned directory, referenced by an index gitlink"""
    sub = repo / "node_modules" / "pkg"
    sub.mkdir(parents=True)
    gg.git("init", "-q", cwd=sub)
    (sub / "v").write_text("v\n")
    gg.git("add", "v", cwd=sub)
    gg.git("commit", "-qm", "v", cwd=sub)
    gg.git("config", "core.fsmonitor", "/tmp/evil", cwd=sub)
    gg.git("add", "-A", cwd=repo)        # creates the gitlink


def attack_index_namelen_desync_hides_gitlink(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[14] forged index: name length in the flags != NUL position → gitguard's
    parser desynchronises and misses the gitlink git honours (node_modules
    pruned → nested_gits blind too; .git/index excluded from the fingerprint)"""
    sub = repo / "node_modules" / "pkg"
    sub.mkdir(parents=True)
    gg.git("init", "-q", cwd=sub)
    (sub / "v").write_text("v\n")
    gg.git("add", "v", cwd=sub)
    gg.git("commit", "-qm", "v", cwd=sub)
    gg.git("config", "core.fsmonitor", "/tmp/evil", cwd=sub)
    gg.git("add", "-A", cwd=repo)        # forms the real gitlink node_modules/pkg
    idx = repo / ".git/index"
    d = bytearray(idx.read_bytes())
    # Entry 1 (file 'f', 64 bytes): announce a 16-byte name in the flags
    # (d[72:74]) but put a real NUL at offset 3 of the name. git consumes 16
    # bytes (→ correct next entry); gitguard stops at the NUL and shifts its
    # offset by 8 bytes, landing in the middle of the real gitlink entry.
    header = bytes(d[0:12])
    fixed = bytes(d[12:72]) + (16).to_bytes(2, "big")
    body = fixed + b"abc\x00DEFGHIJKLMNO"
    body += b"\x00" * (((len(body) + 8) & ~7) - len(body))
    rest = bytes(d[76:-20])              # gitlink entry + extensions, intact
    new = header + body + rest
    idx.write_bytes(new + hashlib.sha1(new).digest())


def attack_nested_git_declared_but_directory(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[6] .git directory declared in .gitmodules: declared != legitimate"""
    (repo / "evil").mkdir()
    gg.git("init", "-q", cwd=repo / "evil")
    gg.git("config", "core.fsmonitor", "/tmp/evil", cwd=repo / "evil")
    (repo / ".gitmodules").write_text('[submodule "evil"]\n\tpath = evil\n\turl = ./evil\n')


def attack_nested_git_in_pruned_dir_declared(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[6] .git planted in a pruned directory (build/) but declared: git descends there"""
    (repo / "build").mkdir()
    gg.git("init", "-q", cwd=repo / "build")
    (repo / ".gitmodules").write_text('[submodule "build"]\n\tpath = build\n\turl = ./build\n')


def attack_second_fake_submodule_after_legit_one(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[9] a legitimate submodule must not hide a second, fake, declared submodule"""
    add_submodule(gg, repo, tmp_path, "aaa")
    gg.trust(repo)
    (repo / "zzz").mkdir()
    gg.git("init", "-q", cwd=repo / "zzz")
    with (repo / ".gitmodules").open("a") as f:
        f.write('[submodule "zzz"]\n\tpath = zzz\n\turl = ./zzz\n')


def attack_submodule_gitfile_redirected(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[7] submodule gitfile redirected to a controlled gitdir outside .git/modules"""
    add_submodule(gg, repo, tmp_path)
    gg.trust(repo)
    shutil.copytree(repo / ".git/modules/sub", repo / "evilgit")
    (repo / "sub/.git").write_text("gitdir: ../evilgit\n")


def attack_gitmodules_modified(gg: GG, repo: Path, tmp_path: Path) -> None:
    """.gitmodules modified (update = !cmd)"""
    add_submodule(gg, repo, tmp_path)
    gg.trust(repo)
    (repo / ".gitmodules").write_text('[submodule "sub"]\n\tpath = sub\n\turl = ./x\n\tupdate = !id\n')


def attack_root_gitfile_into_worktree(gg: GG, repo: Path, tmp_path: Path) -> None:
    """root .git file pointing inside the work tree"""
    (repo / ".git").rename(repo / "evil.git")
    (repo / ".git").write_text("gitdir: evil.git\n")


def attack_submodule_gitdir_volatile_name(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[15] submodule named "lfs": .git/modules/lfs pruned as volatile"""
    add_submodule(gg, repo, tmp_path, "lfs")
    gg.trust(repo)
    with (repo / ".git/modules/lfs/config").open("a") as f:
        f.write("\tfsmonitor = /tmp/evil\n")


def attack_submodule_gitdir_volatile_name_refs(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[15] submodule named "refs": same pruning by name"""
    add_submodule(gg, repo, tmp_path, "refs")
    gg.trust(repo)
    with (repo / ".git/modules/refs/config").open("a") as f:
        f.write("\tfsmonitor = /tmp/evil\n")


def attack_submodule_hook(gg: GG, repo: Path, tmp_path: Path) -> None:
    """hook in .git/modules/<sub>/hooks"""
    from tests.conftest import write_exec
    add_submodule(gg, repo, tmp_path)
    gg.trust(repo)
    write_exec(repo / ".git/modules/sub/hooks/post-checkout")


def attack_submodule_config(gg: GG, repo: Path, tmp_path: Path) -> None:
    """submodule config modified"""
    add_submodule(gg, repo, tmp_path)
    gg.trust(repo)
    gg.git("config", "core.fsmonitor", "/tmp/evil", cwd=repo / "sub")


def attack_bare_gitdir_planted_in_subdir(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[23] bare gitdir (HEAD + objects/ + refs/) planted in src/: git discovers
    it before the parent's .git when git is run from src/"""
    bare = tmp_path / "bare.git"
    assert gg.git("clone", "-q", "--bare", str(repo), str(bare)).rc == 0
    shutil.copytree(bare, repo / "src")
    gg.git("config", "core.fsmonitor", "/tmp/evil", cwd=repo / "src")
    from tests.conftest import write_exec
    write_exec(repo / "src/hooks/reference-transaction")


def attack_gitfile_in_pruned_dir_redirected(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[24] gitfile node_modules/pkg/.git → gitdir outside .git/modules + gitlink
    in the index: nested_gits does not enter node_modules, and the index loop
    only refused a .git directory"""
    sub = repo / "node_modules" / "pkg"
    sub.mkdir(parents=True)
    gg.git("init", "-q", cwd=sub)
    (sub / "v").write_text("v\n")
    gg.git("add", "v", cwd=sub)
    gg.git("commit", "-qm", "v", cwd=sub)
    evil = repo / "node_modules" / "evilgit"      # pruned: invisible to nested_gits
    (sub / ".git").rename(evil)
    (sub / ".git").write_text(f"gitdir: {evil}\n")
    gg.git("config", "core.fsmonitor", "/tmp/evil", cwd=sub)
    gg.git("add", "-A", cwd=repo)        # creates the gitlink
