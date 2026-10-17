"""Tree scan (GITGUARD_SCAN_TREE), off by default.

- With `GITGUARD_SCAN_TREE=1`, the whole attack corpus is refused immediately,
  including the `DEFERRED` attacks of test_attacks.py.
- Without it, a nested repository is only seen once a gitlink exists; the
  `git add -A` that creates it executes nothing (pytest version of the proof
  in tests/nested_git_is_a_threat.sh); `.gitmodules` is always read.
- `safe.bareRepository=explicit` is recommended at trust/retrust/list.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from tests import attacks
from tests.conftest import GG, write_exec
from tests.test_attacks import assert_blocked_now

ATTACKS = attacks.collect()


@pytest.fixture
def gg_scan(gg: GG) -> GG:
    gg.env["GITGUARD_SCAN_TREE"] = "1"
    return gg


@pytest.mark.parametrize("fn", [a[1] for a in ATTACKS], ids=[a[0] for a in ATTACKS])
def test_attack_blocked_immediately_with_scan(gg_scan: GG, repo: Path, tmp_path: Path, fn) -> None:
    assert not gg_scan.check(repo).blocked, "the starting repository must be clean"
    fn(gg_scan, repo, tmp_path)
    assert_blocked_now(gg_scan, repo)


def plant_nested(gg: GG, repo: Path, mark: Path) -> Path:
    """The container: a nested repository with one commit and a config/hooks
    that leave a trace if they execute."""
    sub = repo / "vendor"
    sub.mkdir()
    gg.git("init", "-q", cwd=sub)
    (sub / "v").write_text("v\n")
    gg.git("add", "v", cwd=sub)
    gg.git("commit", "-qm", "v", cwd=sub)
    gg.git("config", "core.fsmonitor", f"sh -c 'touch {mark}; exit 1'", cwd=sub)
    hooks = sub.parent.parent / "hooks"
    gg.git("config", "core.hooksPath", str(hooks), cwd=sub)
    for h in ("post-index-change", "pre-commit", "post-checkout"):
        write_exec(hooks / h, f"#!/bin/sh\ntouch {mark}\n")
    return sub


def test_first_add_does_not_execute(gg: GG, repo: Path, tmp_path: Path) -> None:
    """The assumption that makes the no-scan mode acceptable: the `git add -A`
    that creates the gitlink does not execute the nested repository's config.
    Positive control afterwards: the next command, outside gitguard, does."""
    mark = tmp_path / "EXEC"
    plant_nested(gg, repo, mark)
    assert not gg.check(repo).blocked            # no gitlink: nothing to see
    for cmd in (["status", "--short"], ["diff"], ["stash", "-u"], ["clean", "-nd"]):
        assert gg.run("git", *cmd, cwd=repo).rc == 0, cmd
        assert not mark.exists(), f"git {' '.join(cmd)} executed the nested config"
    r = gg.run("git", "add", "-A", cwd=repo)
    assert r.rc == 0, r.text
    assert not mark.exists(), "the first `git add -A` executes the nested config: " \
                              "the no-scan mode is no longer safe, make the scan the default again"
    assert "160000" in gg.git("ls-files", "--stage", cwd=repo).out, "gitlink expected"
    assert_blocked_now(gg, repo, "nested repository")   # the next command refuses
    # Control: outside gitguard, git does execute from here on.
    gg.git("status", "--short", cwd=repo)
    assert mark.exists(), "invalid control: git no longer executes the nested config"


def test_nested_repo_repair(gg: GG, repo: Path, tmp_path: Path) -> None:
    """Documented repair: delete vendor/.git BEFORE `git rm --cached`."""
    import shutil
    sub = plant_nested(gg, repo, tmp_path / "EXEC")
    assert gg.run("git", "add", "-A", cwd=repo).rc == 0
    r = gg.check(repo)
    assert r.blocked and "vendor/.git" in r.err and "GITGUARD_PRUNE" in r.err
    shutil.rmtree(sub / ".git")
    assert gg.run("git", "rm", "-qf", "--cached", "vendor", cwd=repo).rc == 0
    assert not gg.check(repo).blocked
    assert not (tmp_path / "EXEC").exists()


def test_gitmodules_declared_planted_gitdir_still_refused(gg: GG, repo: Path) -> None:
    """[6] .gitmodules declares a directory (even a pruned one) whose .git is a
    planted directory: read without any tree scan."""
    sub = repo / "build" / "x"
    sub.mkdir(parents=True)
    gg.git("init", "-q", cwd=sub)
    gg.git("config", "core.fsmonitor", "/tmp/evil", cwd=sub)
    (repo / ".gitmodules").write_text('[submodule "x"]\n\tpath = build/x\n\turl = ./x\n')
    assert gg.check(repo).blocked


def test_scan_tree_env_values(gg: GG, repo: Path) -> None:
    (repo / "vendor").mkdir()
    gg.git("init", "-q", cwd=repo / "vendor")
    assert not gg.check(repo).blocked, "off by default"
    for v in ("1", "yes", "true"):
        gg.env["GITGUARD_SCAN_TREE"] = v
        assert gg.check(repo).blocked, v
    for v in ("0", "no", "false", ""):
        gg.env["GITGUARD_SCAN_TREE"] = v
        assert not gg.check(repo).blocked, repr(v)


# ------------------------------------------------------------ safe.bareRepository
NEEDLE = "safe.bareRepository"


def test_safe_bare_warning_at_trust_retrust_list(gg: GG, repo: Path) -> None:
    assert NEEDLE in gg.run("trust", cwd=repo).err
    assert NEEDLE in gg.run("list").err
    assert NEEDLE in gg.run("retrust").err
    assert NEEDLE not in gg.check(repo).err, "not on every command"
    assert NEEDLE not in gg.run("git", "status", cwd=repo).err
    assert gg.git("config", "--global", "safe.bareRepository", "explicit").rc == 0
    gg.trust(repo)                               # the global config changed
    for r in (gg.run("trust", cwd=repo), gg.run("list"), gg.run("retrust")):
        assert r.rc == 0 and NEEDLE not in r.err, r.text


def test_safe_bare_parsed_without_git(gg: GG, repo: Path) -> None:
    """Value read by our parser: key case, last value wins, any value other
    than `explicit` → warning."""
    import gitguard as m
    home = Path(gg.env["HOME"])
    cfg = home / ".gitconfig"
    cfg.write_text(cfg.read_text() + "[Safe]\n\tBareRepository = Explicit\n")
    assert NEEDLE not in gg.run("list").err
    cfg.write_text(cfg.read_text() + "[safe]\n\tbareRepository = all\n")
    assert NEEDLE in gg.run("list").err
    assert m.safe_bare_explicit.__doc__        # public function, exercised above via list
