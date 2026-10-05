#!/bin/sh
# Builds and signs an agent release in one command, and for a test release
# also publishes it to this console.
#
# Test release, on the console server (throwaway key, no questions asked):
#   sudo scripts/release.sh --test
#
# Real release, on the OFFLINE release workstation (never on the console):
#   scripts/release.sh --key /media/usb/minisign.key --version 1.0.0
#   then copy dist/downloads/* into the console's deploy/downloads/ directory.
#
# Options:
#   --test          Sign with a throwaway TEST key and publish to this console's
#                   downloads directory (from deploy/.env). The key is created on
#                   first use in --key-dir, with a random password stored next to
#                   it, and reused afterwards. Agents and install scripts from a
#                   test release trust only that key: fine for a test VM, never
#                   for client machines.
#   --key PATH      Sign with the real release key (it must match
#                   internal/release/minisign.pub). Asks for its password unless
#                   MINISIGN_PASSWORD is set. Does not publish.
#   --version V     Version string (test default: 0.0.0-test.<UTC time>;
#                   required for a real release).
#   --key-dir DIR   Where the test key lives (default: next to this checkout,
#                   in buoy-test-release-key).
#
# Go is used if it is installed; otherwise the build runs in the
# golang:1.26-alpine container (the one the console build uses).
set -eu

die() { echo "release.sh: ERROR: $*" >&2; exit 1; }
say() { echo "==> $*"; }

ROOT=$(cd "$(dirname "$0")/.." && pwd)
CALLER_DIR=$(pwd)
cd "$ROOT"

# abs PATH: PATH made absolute against the directory the script was run from.
abs() { case "$1" in /*) printf '%s' "$1" ;; *) printf '%s/%s' "$CALLER_DIR" "$1" ;; esac; }

MODE=''
KEY=''
VERSION=''
KEYDIR=''
while [ $# -gt 0 ]; do
    case "$1" in
        --test) MODE='test' ;;
        --key|--version|--key-dir)
            [ $# -ge 2 ] || die "$1 needs a value"
            case "$1" in
                --key) MODE='real'; KEY=$(abs "$2") ;;
                --version) VERSION=$2 ;;
                --key-dir) KEYDIR=$(abs "$2") ;;
            esac
            shift
            ;;
        -h|--help) awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"; exit 0 ;;
        *) die "unknown argument $1 (see --help)" ;;
    esac
    shift
done
[ -n "$MODE" ] || die "choose --test (test VM) or --key PATH (real release); see --help"
if [ "$MODE" = test ]; then
    VERSION=${VERSION:-0.0.0-test.$(date -u +%Y%m%d%H%M%S)}
else
    [ -n "$VERSION" ] || die "--version is required for a real release (e.g. --version 1.0.0)"
fi
printf '%s' "$VERSION" | grep -Eq '^[A-Za-z0-9._+-]{1,64}$' || die "--version may only contain letters, digits and . _ + -"

# What the build steps below use. The paths are rewritten for the container.
GEN_KEY=''
if [ "$MODE" = test ]; then
    KEYDIR=${KEYDIR:-$(dirname "$ROOT")/buoy-test-release-key}
    inside_checkout() { case "$1/" in "$ROOT"/*) return 0 ;; esac; return 1; }
    # Checked before and after creating it (the second time with symlinks
    # and .. resolved).
    if inside_checkout "$KEYDIR"; then
        die "--key-dir $KEYDIR is inside this checkout; keep keys outside the repository so they can never be committed (CLAUDE.md rule 4)"
    fi
    KEYDIR_ABS=$(mkdir -p "$KEYDIR" && cd "$KEYDIR" && pwd -P)
    if inside_checkout "$KEYDIR_ABS" || inside_checkout "$(cd "$KEYDIR_ABS" && pwd)"; then
        die "--key-dir $KEYDIR_ABS is inside this checkout; keep keys outside the repository so they can never be committed (CLAUDE.md rule 4)"
    fi
    chmod 0700 "$KEYDIR_ABS"
    if [ ! -f "$KEYDIR_ABS/test.key" ]; then
        say "creating a throwaway TEST signing key in $KEYDIR_ABS"
        old_umask=$(umask)
        umask 077
        head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$KEYDIR_ABS/password"
        umask "$old_umask"
        GEN_KEY=1
    fi
    [ -s "$KEYDIR_ABS/password" ] || die "$KEYDIR_ABS/test.key exists but its password file is missing; delete the directory to start over"
    MINISIGN_PASSWORD=$(cat "$KEYDIR_ABS/password")
    export MINISIGN_PASSWORD
    HOST_KEYDIR=$KEYDIR_ABS
    PUB_NAME=test.pub
    SEC_NAME=test.key
else
    [ -f "$KEY" ] || die "secret key $KEY not found"
    if [ -f deploy/.env ]; then
        die "this checkout has deploy/.env, so it looks like the console server. The release key must never be on the console (CLAUDE.md rule 5): sign on your offline release workstation, then copy dist/downloads/ to the console."
    fi
    HOST_KEYDIR=$(cd "$(dirname "$KEY")" && pwd)
    PUB_NAME=''
    SEC_NAME=$(basename "$KEY")
fi

# Runs from the repository root, on the host or in the container. PUB is
# empty for a real release, so the scripts use the committed public key.
# shellcheck disable=SC2016 # expanded by the inner shell
INNER='set -eu
if [ -n "$GEN_KEY" ]; then go run ./cmd/release-sign keygen -s "$SEC" -p "$PUB" >/dev/null; fi
VERSION="$VERSION" RELEASE_PUBKEY_FILE="$PUB" scripts/build-dist.sh
MINISIGN_SECRET_KEY="$SEC" RELEASE_PUBKEY_FILE="$PUB" scripts/sign-dist.sh
if [ -n "$OWNER" ]; then chown -R "$OWNER" dist; fi'

say "building and signing agent release $VERSION"
export GEN_KEY VERSION
if command -v go >/dev/null 2>&1; then
    PUB=${PUB_NAME:+$HOST_KEYDIR/$PUB_NAME}
    SEC=$HOST_KEYDIR/$SEC_NAME
    OWNER=''
    export PUB SEC OWNER
    sh -c "$INNER"
else
    command -v docker >/dev/null 2>&1 || die "neither Go nor Docker is installed"
    docker info >/dev/null 2>&1 || die "cannot talk to Docker; run with sudo"
    PUB=${PUB_NAME:+/key/$PUB_NAME}
    SEC=/key/$SEC_NAME
    OWNER="$(id -u):$(id -g)"
    export PUB SEC OWNER
    tty=''
    if [ -t 0 ] && [ -t 1 ]; then tty=-t; fi
    # Values travel as environment variables (-e NAME), never on the command line.
    # shellcheck disable=SC2086
    docker run --rm -i $tty -v "$ROOT":/src -w /src -v "$HOST_KEYDIR":/key \
        -v buoy-release-gomod:/go/pkg/mod -v buoy-release-gocache:/root/.cache/go-build \
        -e GOFLAGS=-buildvcs=false -e GEN_KEY -e PUB -e SEC -e VERSION -e OWNER -e MINISIGN_PASSWORD \
        golang:1.26-alpine sh -c "$INNER"
fi

if [ "$MODE" = real ]; then
    echo
    say "release $VERSION is built and signed in $ROOT/dist/downloads"
    echo "    Copy every file from it into the console's deploy/downloads/ directory, for example:"
    echo "      scp dist/downloads/* you@console:/path/to/Lake-Effect-Buoy/deploy/downloads/"
    exit 0
fi

if [ ! -f deploy/.env ]; then
    echo
    say "TEST release $VERSION is built and signed in $ROOT/dist/downloads"
    echo "    No deploy/.env here, so nothing was published. Copy dist/downloads/* into the console's deploy/downloads/."
    exit 0
fi

DL=$(sed -n 's/^CAV_DOWNLOADS_PATH=//p' deploy/.env | tail -n 1)
DL=${DL:-./downloads}
case "$DL" in
    /*) ;;
    *) DL="deploy/${DL#./}" ;;
esac
mkdir -p "$DL" 2>/dev/null || true
if [ ! -d "$DL" ] || [ ! -w "$DL" ]; then die "cannot write to the downloads directory $DL; run with sudo"; fi
cp dist/downloads/* "$DL"/
chmod 0755 "$DL"
chmod a+r "$DL"/*
say "published to $DL"

code=$(curl -sk -o /dev/null -w '%{http_code}' https://127.0.0.1/downloads/install.sh 2>/dev/null || true)
echo
if [ "$code" = 200 ]; then
    say "TEST release $VERSION is live: the console serves /downloads/install.sh"
else
    say "TEST release $VERSION is published, but the console did not answer for /downloads/install.sh (got '${code:-no answer}'); is it running? (cd deploy && docker compose ps)"
fi
echo "    Next: create a NEW enrollment token in the console and paste its command on each endpoint."
echo "    (Commands made before this release do not pin the new Windows installer.)"
echo "    Endpoints already installed upgrade by running their install command again."
echo "    TEST key: agents from this release trust only the key in $KEYDIR_ABS. Never use it for client machines."
