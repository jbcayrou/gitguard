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
