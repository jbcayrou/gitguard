#!/bin/sh
# Build one release of git from kernel.org into a prefix, for the test
# matrix (.github/workflows/tests.yml): the suite takes git as its oracle,
# so each supported version is a job.
#
#   ci/build-git.sh <version> <prefix>      e.g. 2.47.3 ~/git-2.47.3
#
# NO_INSTALL_HARDLINKS: the dashed builtins of the exec path are symlinks
# to `git`, as Debian and Homebrew ship them; tests/conftest.py tells a
# builtin from a helper by that link.
set -eu
[ $# -eq 2 ] || { echo "usage: $0 <version> <prefix>" >&2; exit 2; }
version=$1 prefix=$2
base=https://mirrors.edge.kernel.org/pub/software/scm/git
tarball=git-$version.tar.xz
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"
curl -fsSLO "$base/$tarball"
curl -fsSLO "$base/sha256sums.asc"
# The checksum guards the download, not its origin: the list comes from
# the same server (its PGP signature is not verified here).
grep " $tarball\$" sha256sums.asc > sum
if command -v sha256sum >/dev/null; then sha256sum -c sum; else shasum -a 256 -c sum; fi
tar xf "$tarball"
cd "git-$version"
jobs=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)
make -j"$jobs" prefix="$prefix" NO_GETTEXT=1 NO_TCLTK=1 NO_INSTALL_HARDLINKS=1 install >build.log 2>&1 \
    || { tail -50 build.log >&2; exit 1; }
# As an installed git has it: `git config --system` dies without the directory.
mkdir -p "$prefix/etc"
"$prefix/bin/git" --version
