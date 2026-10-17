"""Shared fixtures: isolated environment, throwaway repositories, gitguard runner.

Nothing touches the machine: HOME, GITGUARD_STATE and the global git config
live in a temporary directory private to each test.
"""
from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
GITGUARD = ROOT / "gitguard.py"
sys.path.insert(0, str(ROOT))


@dataclass
class Result:
    rc: int
    out: str
    err: str

    @property
    def blocked(self) -> bool:
        return self.rc != 0

    @property
    def text(self) -> str:
        return self.out + self.err


@dataclass
class GG:
    """Run gitguard.py (or raw git) in an isolated environment."""
    env: dict[str, str]
    state: Path

    def run(self, *args: str, cwd: Path | None = None, stdin: str | None = None) -> Result:
        r = subprocess.run([sys.executable, str(GITGUARD), *args], cwd=cwd, env=self.env,
                           capture_output=True, text=True, input=stdin, errors="replace")
        return Result(r.returncode, r.stdout, r.stderr)

    def check(self, cwd: Path) -> Result:
        return self.run(cwd=cwd)

    def trust(self, cwd: Path) -> Result:
        r = self.run("trust", cwd=cwd)
        assert r.rc == 0, r.text
        return r

    def git(self, *args: str, cwd: Path | None = None) -> Result:
        """Raw git, bypassing gitguard — to build the scenarios."""
        r = subprocess.run(["git", *args], cwd=cwd, env=self.env, capture_output=True,
                           text=True, errors="replace")
        return Result(r.returncode, r.stdout, r.stderr)

    def key_for(self, root: Path) -> Path:
        import hashlib
        return self.state / hashlib.sha256(str(root.resolve()).encode()).hexdigest()[:16]


@pytest.fixture
def gg(tmp_path: Path) -> GG:
    home = tmp_path / "home"
    state = tmp_path / "state"
    home.mkdir()
    env = {
        "PATH": os.environ["PATH"],
        "HOME": str(home),
        "GITGUARD_STATE": str(state),
        "GIT_CONFIG_NOSYSTEM": "1",
        "NO_COLOR": "1",
        "LC_ALL": "C.UTF-8",
    }
    g = GG(env, state)
    for k, v in [("user.email", "t@t"), ("user.name", "t"), ("init.defaultBranch", "main"),
                 ("protocol.file.allow", "always")]:
        assert g.git("config", "--global", k, v).rc == 0
    return g


@pytest.fixture
def repo(gg: GG, tmp_path: Path) -> Path:
    """Clean repository with one commit, trusted by gitguard."""
    r = tmp_path / "repo"
    assert gg.git("init", "-q", str(r)).rc == 0
    (r / "f").write_text("a\n")
    assert gg.git("add", "f", cwd=r).rc == 0
    assert gg.git("commit", "-qm", "init", cwd=r).rc == 0
    gg.trust(r)
    return r


@pytest.fixture
def subsrc(gg: GG, tmp_path: Path) -> Path:
    """Small source repository for submodules and clones."""
    s = tmp_path / "subsrc"
    assert gg.git("init", "-q", str(s)).rc == 0
    (s / "s").write_text("s\n")
    assert gg.git("add", "s", cwd=s).rc == 0
    assert gg.git("commit", "-qm", "s", cwd=s).rc == 0
    return s


def write_exec(p: Path, body: str = "#!/bin/sh\nid\n") -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body)
    p.chmod(0o755)
