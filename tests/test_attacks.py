"""Every attack pattern in tests/attacks/ must be refused by gitguard.

Properties checked for each:
1. ``gitguard`` alone refuses (exit != 0);
2. ``gitguard git status`` does not run git;
3. the repository was not already alerting before the attack (otherwise the
   test proves nothing) — guaranteed by the fixture, re-checked here.

A nested repository that has no gitlink yet is not visible: git does not
open it either. For those attacks (``DEFERRED``), we check that the next
barrier holds — the user's ``git add -A`` goes through (and executes nothing:
``test_nested.py::test_first_add_does_not_execute``), then the next command
is refused; or, for a planted bare gitdir, that git is refused as soon as it
is run from that directory.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from tests import attacks
from tests.conftest import GG

ATTACKS = attacks.collect()

# Attacks not visible before the gitlink (no walk of the tree): what the
# user does next, and from where gitguard must then refuse.
# Traps in a sequence's files (todo, strategy, sequencer opts): read only by
# a command that can resume the sequence ([147]). The plain check still
# refuses; the resuming command must be refused, an ordinary one may run.
RESUME = {
    "attack_rebase_todo_exec": ["rebase", "--continue"],
    "attack_rebase_todo_exec_tab": ["rebase", "--continue"],
    "attack_rebase_strategy_binary": ["rebase", "--continue"],
    "attack_rebase_strategy_trailing_blank": ["rebase", "--continue"],
    "attack_rebase_strategy_trailing_cr": ["rebase", "--continue"],
    "attack_rebase_strategy_empty": ["rebase", "--continue"],
    "attack_rebase_strategy_tree_path": ["rebase", "--continue"],
    "attack_sequencer_opts_strategy": ["cherry-pick", "--continue"],
    "attack_sequencer_opts_strategy_lone_cr": ["cherry-pick", "--continue"],
    "attack_rebase_todo_exec_in_submodule": ["submodule", "foreach", "-q", "git rebase --continue"],
    "attack_rebase_todo_exec_resumed_by_a_child": ["commit", "--allow-empty", "-qm", "x"],
}

DEFERRED = {
    "attack_nested_git_undeclared": ("add", None),
    "attack_bare_gitdir_planted_in_subdir": ("cd", "src"),
    "attack_env_common_dir_head_planted_in_subdir": ("cd", "src"),
}

# Trees planted next to a trusted repository to take its trust ([154]):
# the repository itself is as it was, git run from the planted tree is
# refused.
NO_INHERIT = {
    "attack_gitfile_copy_of_a_trusted_submodule": "src",
    "attack_gitfile_copy_of_a_trusted_worktree": "src",
    "attack_worktree_gitdir_planted_in_a_volatile_zone": "src",
}


# Known open flaws: the attack is in the corpus, the refusal is not there yet.
# xfail(strict): a fix makes the test XPASS, then remove the entry.
OPEN = {
    "attack_alias_script_after_cd": "[71] accepted limitation (DESIGN.md, Known limitations)",
    "attack_alias_script_in_subshell_after_cd": "[71] accepted limitation (DESIGN.md, Known limitations)",
    "attack_alias_script_glued_to_empty_variable": "[74] accepted limitation (DESIGN.md, Known limitations)",
    "attack_active_submodule_gitlink_in_head_runs_in_process":
        "[126] no refusal: the in-process entry is disarmed by the fsmonitor pin "
        "(PINNED_CONFIG, test_claims.py), git runs",
}


def assert_blocked_now(gg: GG, cwd: Path, needle: str | None = None) -> None:
    r = gg.check(cwd)
    assert r.blocked, f"attack accepted!\n{r.text}"
    assert "gitguard:" in r.err
    if needle:
        assert needle in r.err, r.text
    r2 = gg.run("git", "status", cwd=cwd)
    assert r2.blocked and "On branch" not in r2.out, "git ran despite the attack"


@pytest.mark.parametrize("fn", [
    pytest.param(fn, marks=pytest.mark.xfail(strict=True, reason=OPEN[fn.__name__]))
    if fn.__name__ in OPEN else fn for _, fn in ATTACKS], ids=[a[0] for a in ATTACKS])
def test_attack_is_blocked(gg: GG, repo: Path, tmp_path: Path, fn) -> None:
    assert not gg.check(repo).blocked, "the starting repository must be clean"
    fn(gg, repo, tmp_path)
    resume = RESUME.get(fn.__name__)
    if resume is not None:
        r = gg.check(repo)
        assert r.blocked and "gitguard:" in r.err, f"attack accepted!\n{r.text}"
        r2 = gg.run("git", *resume, cwd=repo)
        assert r2.blocked and "gitguard:" in r2.err, f"the resuming command ran\n{r2.text}"
        return
    planted = NO_INHERIT.get(fn.__name__)
    if planted is not None:
        assert not gg.check(repo).blocked          # nothing of the repository changed
        assert_blocked_now(gg, repo / planted)
        assert "trusted with" not in gg.check(repo / planted).err
        return
    deferred = DEFERRED.get(fn.__name__)
    if deferred is None:
        assert_blocked_now(gg, repo)
        return
    kind, arg = deferred
    if kind == "add":
        assert not gg.check(repo).blocked          # no early warning…
        assert gg.git("add", "-A", cwd=repo).rc == 0
        assert_blocked_now(gg, repo, "nested repository")   # …refused once the gitlink exists
    else:
        assert_blocked_now(gg, repo / arg, "bare gitdir")


def test_deferred_list_matches_corpus() -> None:
    names = {a[1].__name__ for a in ATTACKS}
    assert set(DEFERRED) <= names, set(DEFERRED) - names
    assert set(RESUME) <= names, set(RESUME) - names
    assert set(OPEN) <= names, set(OPEN) - names
    assert set(NO_INHERIT) <= names, set(NO_INHERIT) - names


def test_corpus_is_not_empty() -> None:
    assert len(ATTACKS) >= 30, [a[0] for a in ATTACKS]


def test_catalogue_cross_references() -> None:
    """The rule "a flaw is a test first" checked mechanically: every `[n]`
    cited in gitguard.py or in a test exists in the catalogue of
    tests/attacks/__init__.py, and every catalogue entry is cited by at
    least one test. The lookbehind leaves out indexing (`argv[0]`, `x)[0]`,
    `x][0]`) and the `3[1236]` of a regex; a `[0]` is a list literal."""
    import re
    root = Path(__file__).resolve().parent.parent
    catalogue_file = root / "tests/attacks/__init__.py"
    catalogue = {int(n) for n in re.findall(r"^\s*\[(\d+)\]", catalogue_file.read_text(encoding="utf-8"), re.M)}
    assert catalogue, "no catalogue entry found"
    cite = re.compile(r"(?<![\w)\]])\[(\d+)\]")

    def cited(p: Path) -> set[int]:
        return {int(n) for n in cite.findall(p.read_text(encoding="utf-8")) if int(n) > 0}   # `[0]`: a list

    code = cited(root / "gitguard.py")
    tests: set[int] = set()
    for p in root.glob("tests/**/*.py"):
        if p != catalogue_file:
            tests |= cited(p)
    assert (code | tests) <= catalogue, sorted((code | tests) - catalogue)
    assert catalogue <= tests, f"catalogue entries no test cites: {sorted(catalogue - tests)}"
