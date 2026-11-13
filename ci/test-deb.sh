#!/bin/sh
# The life of the package on a machine, replayed against the distribution's
# own git: install, an upgrade of git, an upgrade of gitguard, remove,
# purge, the take-over of the README's hand-made install, the removal of
# git itself. After each: either git is wrapped at both names with the
# distribution's binaries intact beside them, or the machine is as if the
# package had never been there — same bytes, no diversion left.
#
# It installs and removes git, as root: in a throwaway container only.
#
#   docker run --rm -v "$PWD":/src:ro debian:13 sh -c \
#       'cp -r /src /w && cd /w && GITGUARD_DEB_TEST=throwaway ci/test-deb.sh'
set -eu
if [ "${GITGUARD_DEB_TEST:-}" != throwaway ] || [ "$(id -u)" != 0 ]; then
    echo "ci/test-deb.sh installs and removes git: run it as root in a throwaway" >&2
    echo "container, with GITGUARD_DEB_TEST=throwaway (see its header)." >&2
    exit 2
fi
here=$(cd "$(dirname "$0")/.." && pwd)
export DEBIAN_FRONTEND=noninteractive
BIN=/usr/bin/git CORE=/usr/lib/git-core/git

say() { printf '\n== %s\n' "$*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
sum() { sha256sum "$1" | cut -d' ' -f1; }
apt() { apt-get -qy -o Dpkg::Use-Pty=0 "$@" >/tmp/apt.log 2>&1 || { cat /tmp/apt.log >&2; fail "apt-get $*"; }; }
diversions() { dpkg-divert --list | grep -c gitguard || true; }
as_user() { su user -c "cd /home/user && export GITGUARD_STATE=/home/user/state GITGUARD_WAIT=0 GITGUARD_NO_NOTIFY=1 && $1"; }

wrapped() {      # git is gitguard at both names, the distribution's binaries beside them
    [ "$(readlink $BIN)" = gitguard ] || fail "$BIN is not the package's link"
    [ "$(readlink -f $CORE)" = /usr/bin/gitguard ] || fail "$CORE does not lead to gitguard"
    [ "$(sum $BIN.real)" = "$real_bin" ] || fail "$BIN.real is not the distribution's git"
    [ "$(sum $CORE.real)" = "$real_core" ] || fail "$CORE.real is not the distribution's git"
    [ "$(diversions)" = 2 ] || fail "expected two diversions: $(dpkg-divert --list)"
    git --version | grep -q '^git version' || fail "git --version"
    # It guards, as a user: a new repository is trusted, a hook planted
    # behind its back refuses the next git, under the dashed name of the
    # exec path too, and `trust` has nothing to say about the exec path.
    rm -rf /home/user/r /home/user/state
    as_user 'git init -q r' 2>&1 | grep -q 'new repository trusted' || fail "git init did not go through gitguard"
    as_user 'printf "#!/bin/sh\n" > r/.git/hooks/pre-commit && chmod +x r/.git/hooks/pre-commit'
    for g in git /usr/lib/git-core/git-status; do
        if as_user "cd r && $g status" >/tmp/out 2>&1; then fail "$g ran on a changed repository"; fi
        grep -q 'has changed since the last trust' /tmp/out || { cat /tmp/out >&2; fail "$g: not gitguard's refusal"; }
    done
    as_user 'cd r && gitguard trust' >/tmp/out 2>&1 || { cat /tmp/out >&2; fail "gitguard trust"; }
    if grep -q 'does not lead to gitguard\|stale exec path' /tmp/out; then cat /tmp/out >&2; fail "exec path not wrapped"; fi
    as_user 'cd r && git status' >/dev/null 2>&1 || fail "git refused a trusted repository"
}

pristine() {     # as if the package had never been installed
    for f in $BIN $CORE; do
        [ -f $f ] && [ ! -L $f ] || fail "$f is not a regular file"
        [ ! -e $f.real ] && [ ! -L $f.real ] || fail "$f.real left behind"
    done
    [ "$(sum $BIN)" = "$real_bin" ] && [ "$(sum $CORE)" = "$real_core" ] || fail "git is not the distribution's bytes"
    [ ! -e /usr/bin/gitguard ] || fail "/usr/bin/gitguard left behind"
    [ "$(diversions)" = 0 ] || fail "diversion left behind: $(dpkg-divert --list)"
    rm -rf /home/user/r
    if as_user 'git init -q r' 2>&1 | grep -q gitguard; then fail "git is still gitguard"; fi
}

say "the distribution's git"
apt update
apt install --no-install-recommends git python3
id user >/dev/null 2>&1 || useradd -m user
[ -f $BIN ] && [ ! -L $BIN ] && [ -f $CORE ] && [ ! -L $CORE ] || fail "expected two regular files: $BIN, $CORE"
real_bin=$(sum $BIN) real_core=$(sum $CORE)
git --version
deb=$("$here/ci/build-deb.sh" /tmp/deb)
[ "$(python3 "$here/gitguard.py" version)" = "gitguard $(dpkg-deb -f "$deb" Version)" ] || fail "the package's version is not gitguard's"
next=$(DEB_VERSION=99.0.0 "$here/ci/build-deb.sh" /tmp/deb)
dpkg-deb --info "$deb" | sed -n 's/^ \(Package\|Version\|Depends\|Maintainer\)/\1/p'

say "install"
apt install "$deb"
wrapped

say "git reinstalled by apt (an upgrade of git): dpkg writes at the diverted names"
apt install --reinstall git
wrapped

say "upgrade of gitguard: the diversions stay"
apt install "$next"
[ "$(dpkg-query -W -f '${Version}' gitguard)" = 99.0.0 ] || fail "not upgraded"
wrapped

say "remove"
apt remove gitguard
pristine

say "install, purge"
apt install "$deb"
wrapped
apt purge gitguard
pristine

say "the README's hand-made install, taken over by the package, then removed"
dpkg-deb --fsys-tarfile "$deb" | tar -xO ./usr/bin/gitguard > /usr/bin/gitguard
chmod 755 /usr/bin/gitguard
dpkg-divert --package gitguard --add --rename --divert $BIN.real $BIN >/dev/null
ln -s gitguard $BIN
dpkg-divert --package gitguard --add --rename --divert $CORE.real $CORE >/dev/null
ln -s /usr/bin/gitguard $CORE
apt install "$deb"
wrapped
apt remove gitguard
pristine

say "git removed while gitguard is installed: both go, nothing is left"
apt install "$deb"
apt remove git
for f in $BIN $BIN.real $CORE $CORE.real /usr/bin/gitguard; do
    [ ! -e $f ] && [ ! -L $f ] || fail "$f left behind"
done
[ "$(diversions)" = 0 ] || fail "diversion left behind: $(dpkg-divert --list)"
apt install --no-install-recommends git
pristine

say "ok"
