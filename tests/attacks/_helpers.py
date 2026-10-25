"""Constructions shared by the attack modules (not attacks themselves)."""
from __future__ import annotations

import subprocess
from pathlib import Path

from tests.conftest import GG


def make_source(gg: GG, tmp_path: Path, name: str = "subsrc") -> Path:
    s = tmp_path / name
    if not s.exists():
        assert gg.git("init", "-q", str(s)).rc == 0
        (s / "s").write_text("s\n")
        assert gg.git("add", "s", cwd=s).rc == 0
        assert gg.git("commit", "-qm", "s", cwd=s).rc == 0
    return s


def add_submodule(gg: GG, repo: Path, tmp_path: Path, name: str = "sub") -> Path:
    """Add a real submodule `name` and commit it. Returns its path."""
    src = make_source(gg, tmp_path)
    r = gg.git("-c", "protocol.file.allow=always", "submodule", "add", "-q", str(src), name, cwd=repo)
    assert r.rc == 0, r.text
    assert gg.git("commit", "-qm", "sub", cwd=repo).rc == 0
    return repo / name


def forge_index(gg: GG, repo: Path, extra: list[tuple[int, bytes, bytes]],
                gitdir: Path | None = None) -> None:
    """Rewrite the index of `repo` (or of `gitdir`, for a submodule) by hand:
    its current entries plus `extra` = (mode, content, name). Written as raw
    bytes, as a sandbox would: `git update-index` refuses the invalid names
    (verify_path), `checkout -- .` and `restore --worktree` do not. [55]"""
    import hashlib
    gitdir = gitdir or repo / ".git"
    entries = []
    for rec in gg.git("ls-files", "-s", "-z", cwd=repo).out.split("\0"):
        if rec:
            meta, name = rec.split("\t", 1)
            mode, sha, _ = meta.split()
            entries.append((int(mode, 8), bytes.fromhex(sha), name.encode()))
    for mode, content, name in extra:
        blob = subprocess.run(["git", "hash-object", "-w", "--stdin"], cwd=repo, env=gg.env,
                              input=content, capture_output=True, check=True).stdout
        entries.append((mode, bytes.fromhex(blob.decode().strip()), name))
    body = b"DIRC" + (2).to_bytes(4, "big") + len(entries).to_bytes(4, "big")
    for mode, sha, name in sorted(entries, key=lambda e: e[2]):
        e = b"\0" * 24 + mode.to_bytes(4, "big") + b"\0" * 12 + sha
        e += min(len(name), 0xFFF).to_bytes(2, "big") + name
        e += b"\0" * (((len(e) + 8) & ~7) - len(e))
        body += e
    (gitdir / "index").write_bytes(body + hashlib.sha1(body).digest())


# Index entry names git refuses in verify_path when it reads a tree, but
# writes as is from an index (`checkout -- .`, `restore --worktree`,
# `checkout-index`): name -> where the file lands, relative to the repository
# root. `None`: absolute, landing at `tmp_path / "abs-escaped"`. [55]
INDEX_ESCAPES = {
    "into_gitdir": (b".git/hooks/post-checkout", ".git/hooks/post-checkout"),
    "dotgit_case": (b".GIT/hooks/post-checkout", ".git/hooks/post-checkout"),
    "dot_component": (b"./.git/hooks/post-checkout", ".git/hooks/post-checkout"),
    "dotdot_inside": (b"x/../.git/hooks/post-checkout", ".git/hooks/post-checkout"),
    "empty_component": (b"x//../.git/hooks/post-checkout", ".git/hooks/post-checkout"),
    "dotdot_out": (b"../escaped", "../escaped"),
}


# ------------------------------------------------ features of the git under test
# Probed on the git the scenarios use (REAL_GIT), never by version number: a
# positive control that needs a feature skips when that git lacks it, the
# attack itself does not (gitguard must watch both readings of the value).
_FEATURES: dict[str, bool] = {}


def git_has(feature: str) -> bool:
    """`alias_subsection`: `[alias "x"] command = …` (git 2.54).
    `config_hooks`: `hook.<name>.command` + `hook.<name>.event` (git 2.54).
    `optional_path`: the `:(optional)` prefix of a pathname value (git 2.52+)."""
    if feature not in _FEATURES:
        import os
        import tempfile
        from tests.conftest import REAL_GIT
        with tempfile.TemporaryDirectory() as d:
            env = {"PATH": os.environ["PATH"], "HOME": d, "GIT_CONFIG_NOSYSTEM": "1"}
            run = lambda *a: subprocess.run([REAL_GIT, *a], cwd=d, env=env,
                                            capture_output=True, text=True)
            if feature == "alias_subsection":
                ok = run("-c", "alias.zz.command=version", "zz").returncode == 0
            elif feature == "config_hooks":
                run("init", "-q", ".")
                r = run("-c", "hook.t.command=echo HOOKRAN", "-c",
                        "hook.t.event=pre-commit", "hook", "run", "pre-commit")
                ok = "HOOKRAN" in r.stdout + r.stderr      # a hook's stdout goes to stderr
            elif feature == "optional_path":
                ok = run("-c", "x.y=:(optional)/", "config", "--type=path", "x.y").stdout == "/\n"
            else:
                raise ValueError(feature)
        _FEATURES[feature] = ok
    return _FEATURES[feature]


# ------------------------------------- sandboxes of the review of 2026-10-24 (2)
# Shared by the attack (gitguard must refuse at the check) and its positive
# control in test_commands.py (the real git, same planting, runs the payload).
def _git_input(gg: GG, cwd: Path, text: str, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=cwd, env=gg.env, input=text,
                          capture_output=True, text=True, check=True).stdout.strip()


def plant_sparse_gitlink(gg: GG, repo: Path, tmp_path: Path, fsmonitor: str) -> None:
    """[87] The user: a cone sparse-checkout of `src/`, `vendor/` outside the
    cone, trusted. The sandbox: a tree for `vendor/` with a gitlink
    `vendor/evil` (objects are volatile), a sparse index (`sdir`, vendor/ one
    040000 entry: the index is volatile) written by its own git, and the
    nested repository `vendor/evil` in the tree, its core.fsmonitor set to
    `fsmonitor`. `.git/config` is not touched."""
    (repo / "src").mkdir()
    (repo / "src/s").write_text("s\n")
    (repo / "vendor").mkdir()
    (repo / "vendor/v").write_text("v\n")
    assert gg.git("add", ".", cwd=repo).rc == 0
    assert gg.git("commit", "-qm", "tree", cwd=repo).rc == 0
    assert gg.git("sparse-checkout", "set", "--cone", "src", cwd=repo).rc == 0
    gg.trust(repo)
    # the sandbox
    evil = make_source(gg, tmp_path, "evil-src")
    sha = gg.git("rev-parse", "HEAD", cwd=evil).out.strip()
    vt = _git_input(gg, repo, gg.git("ls-tree", "HEAD:vendor", cwd=repo).out
                    + f"160000 commit {sha}\tevil\n", "mktree", "--missing")
    lines = [ln if not ln.endswith("\tvendor") else f"040000 tree {vt}\tvendor"
             for ln in gg.git("ls-tree", "HEAD", cwd=repo).out.splitlines()]
    rt = _git_input(gg, repo, "\n".join(lines) + "\n", "mktree", "--missing")
    r = gg.git("-c", "index.sparse=true", "-c", "core.sparseCheckout=true",
               "-c", "core.sparseCheckoutCone=true", "read-tree", "-m", "-u", "HEAD", rt, cwd=repo)
    assert r.rc == 0, r.text
    assert b"sdir" in (repo / ".git/index").read_bytes(), "the sandbox's index is not sparse"
    import shutil
    (repo / "vendor").mkdir(exist_ok=True)
    (repo / "vendor/v").write_text("v\n")
    shutil.copytree(evil / ".git", repo / "vendor/evil/.git")
    assert gg.git("config", "core.fsmonitor", fsmonitor, cwd=repo / "vendor/evil").rc == 0


def hardlink_editmsg_to_hook(gg: GG, repo: Path, hook: Path, payload: str) -> None:
    """[88] The user has a trusted, executable `hook` (commit-msg). The
    sandbox: a commit whose message is `payload` (shell) moved to HEAD
    (objects, refs: volatile), and `.git/COMMIT_EDITMSG` (volatile) replaced
    by a hard link to the hook — same inode, the hook's bytes unchanged. `git
    commit --amend` writes the message into COMMIT_EDITMSG, i.e. into the
    hook, then runs it."""
    (repo / "work.txt").write_text("the sandbox's work\n")     # an amend that is not empty
    assert gg.git("add", "work.txt", cwd=repo).rc == 0
    tree = gg.git("write-tree", cwd=repo).out.strip()
    c = _git_input(gg, repo, f"subject\n\n{payload}\n", "commit-tree", tree, "-p", "HEAD")
    assert gg.git("update-ref", "HEAD", c, cwd=repo).rc == 0
    import os
    msg = repo / ".git/COMMIT_EDITMSG"
    msg.unlink(missing_ok=True)
    os.link(hook, msg)
    assert hook.stat().st_nlink == 2


def submodule_source_with(gg: GG, tmp_path: Path, files: dict[str, str]) -> Path:
    """The upstream of a submodule carrying executable `files` (a hooks
    directory, a convention script), with a second commit: `add_submodule`
    takes it (same name as make_source's), and a submodule left one commit
    behind gives `git submodule update` a checkout to do."""
    s = tmp_path / "subsrc"
    assert gg.git("init", "-q", str(s)).rc == 0
    for rel, body in files.items():
        (s / rel).parent.mkdir(parents=True, exist_ok=True)
        (s / rel).write_text(body)
        (s / rel).chmod(0o755)
    assert gg.git("add", ".", cwd=s).rc == 0
    assert gg.git("commit", "-qm", "one", cwd=s).rc == 0
    assert gg.git("commit", "-q", "--allow-empty", "-m", "two", cwd=s).rc == 0
    return s


def payload(tmp_path: Path) -> Path:
    """An executable that touches `tmp_path/RAN`. The attacks of an open
    finding use it rather than `/tmp/evil`: while the attack is not refused,
    the `git status` of test_attack_is_blocked really runs, and a planted
    fsmonitor with it."""
    p = tmp_path / "payload.sh"
    p.write_text(f"#!/bin/sh\ntouch '{tmp_path}/RAN'\nexit 1\n")
    p.chmod(0o755)
    return p
