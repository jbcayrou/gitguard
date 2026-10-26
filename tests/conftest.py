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


def _is_gitguard(p: Path) -> bool:
    try:
        with open(p, "rb") as f:
            return b"gitguard" in f.read(512)
    except OSError:
        return False


def _real_git() -> str:
    """The git the scenarios are built with. On a machine with the system-wide
    install, the `git` of the PATH is already gitguard (`/usr/bin/git →
    gitguard`, the real one diverted to `git.real`): every scenario would then
    be refused as "never trusted" by the test's own isolated state."""
    if os.environ.get("GITGUARD_REAL_GIT"):
        return os.environ["GITGUARD_REAL_GIT"]
    for d in os.environ.get("PATH", os.defpath).split(os.pathsep):
        for name in ("git", "git.real"):
            cand = Path(d or ".") / name
            if cand.is_file() and os.access(cand, os.X_OK) and not _is_gitguard(cand):
                return str(cand)
    raise RuntimeError("no git other than gitguard in the PATH: set GITGUARD_REAL_GIT")


REAL_GIT = _real_git()


def _exec_paths(base: Path) -> tuple[Path, Path]:
    """Two exec paths (DESIGN-exec-path.md). The scenarios are built with the
    real git and **raw** children (`raw/git` is the real binary), the checks
    run with the **wrapped** exec path (`wrapped/git` is gitguard, `git.real`
    next to it): git puts the exec path first in its children's PATH, so a
    child git of the checked command is gitguard, as it is on a machine
    where the exec path is diverted. Every other entry of the real exec
    path (helpers, scripts) is linked into both."""
    r = subprocess.run([REAL_GIT, "--exec-path"], capture_output=True, text=True)
    real_core = Path(r.stdout.strip())
    real_bin = real_core / "git.real" if (real_core / "git.real").exists() else real_core / "git"
    if _is_gitguard(real_bin):
        raise RuntimeError(f"{real_bin} is gitguard and no git.real sits next to it")
    raw, wrapped = base / "exec-raw", base / "exec-wrapped"
    git_inode = (real_core / "git").resolve()
    for d in (raw, wrapped):
        d.mkdir()
        for n in os.listdir(real_core):
            if n in ("git", "git.real"):
                continue
            if (real_core / n).resolve() == git_inode:
                os.symlink("git", d / n)       # a dashed builtin: `git` of this directory
            else:
                os.symlink(real_core / n, d / n)
    os.symlink(real_bin, raw / "git")
    os.symlink(GITGUARD, wrapped / "git")
    os.symlink(real_bin, wrapped / "git.real")
    return raw, wrapped


def pytest_report_header(config) -> str:
    """Which git the parity tests took as the oracle: the discovery ports
    (`-m discovery`) and the byte-variant tables were checked against it."""
    r = subprocess.run([REAL_GIT, "--version"], capture_output=True, text=True)
    return f"git oracle: {REAL_GIT} ({r.stdout.strip() or 'version unknown'})"


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
    """Run gitguard.py (or raw git) in an isolated environment. `env` has the
    wrapped exec path (a child git of a checked command is gitguard);
    `raw_env` the raw one, for building scenarios and for positive controls
    that need the real git to enter a repository."""
    env: dict[str, str]
    state: Path
    raw_exec: Path = Path("/nonexistent")

    @property
    def raw_env(self) -> dict[str, str]:
        return {**self.env, "GIT_EXEC_PATH": str(self.raw_exec)}

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
        r = subprocess.run(["git", *args], cwd=cwd, env=self.raw_env, capture_output=True,
                           text=True, errors="replace")
        return Result(r.returncode, r.stdout, r.stderr)

    def key_for(self, root: Path) -> Path:
        import hashlib
        return self.state / hashlib.sha256(str(root.resolve()).encode()).hexdigest()[:16]


@pytest.fixture(scope="session")
def exec_paths(tmp_path_factory) -> tuple[Path, Path]:
    return _exec_paths(tmp_path_factory.mktemp("exec"))


@pytest.fixture
def gg(tmp_path: Path, exec_paths: tuple[Path, Path]) -> GG:
    raw, wrapped = exec_paths
    home = tmp_path / "home"
    state = tmp_path / "state"
    home.mkdir()
    realgit = tmp_path / "bin-real-git"     # `git` = the real one, ahead of the PATH
    realgit.mkdir()
    os.symlink(REAL_GIT, realgit / "git")
    env = {
        "PATH": f"{realgit}{os.pathsep}{os.environ['PATH']}",
        "HOME": str(home),
        "GITGUARD_STATE": str(state),
        "GIT_CONFIG_NOSYSTEM": "1",
        "NO_COLOR": "1",
        "LC_ALL": "C.UTF-8",
        "GITGUARD_NO_NOTIFY": "1",   # the suite never notifies a developer's desktop
        "GITGUARD_WAIT": "0",        # nor blocks: the waiting tests set their own value
        "GIT_EXEC_PATH": str(wrapped),
    }
    g = GG(env, state, raw)
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
