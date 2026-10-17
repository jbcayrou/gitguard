"""Constructions shared by the attack modules (not attacks themselves)."""
from __future__ import annotations

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
