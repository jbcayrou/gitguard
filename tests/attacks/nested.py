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


def attack_gitlink_in_submodule_index(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[60] nested repository inside a submodule's tree, referenced by a
    gitlink of the submodule's index (`.git/modules/sub/index`): that index
    was parsed for forged names [55] but its gitlinks were dropped, and
    `git status` in the superproject recurses into sub, then into the nested
    repository, whose core.fsmonitor runs"""
    sub = add_submodule(gg, repo, tmp_path)
    gg.trust(repo)
    inner = sub / "inner"
    gg.git("init", "-q", str(inner))
    (inner / "i").write_text("i\n")
    gg.git("add", "i", cwd=inner)
    gg.git("commit", "-qm", "i", cwd=inner)
    gg.git("config", "core.fsmonitor", "/tmp/evil", cwd=inner)
    assert gg.git("add", "inner", cwd=sub).rc == 0          # the gitlink, in sub's index


def attack_nested_git_declared_in_submodule_gitmodules(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[60] a nested .git directory declared in the submodule's own
    .gitmodules (no gitlink needed for the declaration to be read)"""
    sub = add_submodule(gg, repo, tmp_path)
    gg.trust(repo)
    inner = sub / "inner"
    gg.git("init", "-q", str(inner))
    gg.git("config", "core.fsmonitor", "/tmp/evil", cwd=inner)
    (sub / ".gitmodules").write_text('[submodule "inner"]\n\tpath = inner\n\turl = ./x\n')


def attack_gitlink_in_submodule_index_gitfile_outside(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[60] the nested entry of the submodule's index is a gitfile pointing
    outside the submodule's modules/ (a gitdir the container controls)"""
    sub = add_submodule(gg, repo, tmp_path)
    gg.trust(repo)
    evil = tmp_path / "vol-evil"
    gg.git("init", "-q", str(evil))
    (evil / "e").write_text("e\n")
    gg.git("add", "e", cwd=evil)
    gg.git("commit", "-qm", "e", cwd=evil)
    gg.git("config", "core.fsmonitor", "/tmp/evil", cwd=evil)
    # only the volatile index and the tree: no watched file of .git changes
    sha = gg.git("rev-parse", "HEAD", cwd=evil).out.strip()
    assert gg.git("update-index", "--add", "--cacheinfo", f"160000,{sha},inner", cwd=sub).rc == 0
    (sub / "inner").mkdir()
    (sub / "inner/.git").write_text(f"gitdir: {evil / '.git'}\n")


def attack_sparse_index_hides_gitlink(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[87] sparse index: the gitlink `vendor/evil` sits in a 040000
    directory entry (`sdir`) the index parser does not expand; git expands
    it once `vendor/` is on disk and `git status` runs the planted fsmonitor
    (positive control: test_commands)"""
    from tests.attacks._helpers import payload, plant_sparse_gitlink
    plant_sparse_gitlink(gg, repo, tmp_path, str(payload(tmp_path)))


def attack_gitdir_in_submodule_volatile_zone(gg: GG, repo: Path, tmp_path: Path) -> None:
    """[103] a gitdir planted in a volatile zone of a real submodule's gitdir
    (`.git/modules/sub/refs/p`: nobody hashes refs/), named by a gitlink of
    the submodule's index (volatile) through a gitfile: check_nested_git
    accepted anything under modules/, and `git status` recursed into it"""
    sub = add_submodule(gg, repo, tmp_path)
    gg.trust(repo)
    planted = tmp_path / "vol-planted"
    gg.git("init", "-q", str(planted))
    (planted / "p").write_text("p\n")
    gg.git("add", "p", cwd=planted)
    gg.git("commit", "-qm", "p", cwd=planted)
    gg.git("config", "core.fsmonitor", "/tmp/evil", cwd=planted)
    pg = repo / ".git/modules/sub/refs/p"
    shutil.move(str(planted / ".git"), str(pg))
    sha = gg.git("--git-dir", str(pg), "rev-parse", "HEAD").out.strip()
    assert gg.git("update-index", "--add", "--cacheinfo", f"160000,{sha},inner", cwd=sub).rc == 0
    (sub / "inner").mkdir()
    (sub / "inner/.git").write_text("gitdir: ../../.git/modules/sub/refs/p\n")
