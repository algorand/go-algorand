#!/bin/bash

set -ex

echo "Building RPM package"

OS_TYPE="$1"
ARCH="$2"
WORKDIR="$3"

if [ -z "$OS_TYPE" ] || [ -z "$ARCH" ] || [ -z "$WORKDIR" ]; then
    echo OS, ARCH and WORKDIR variables must be defined.
    exit 1
fi

export REPO_DIR="$WORKDIR"
export GOPATH="$REPO_DIR/go"
# TODO: Should there be a default network?
export DEFAULTNETWORK=devnet

DEFAULT_RELEASE_NETWORK=$("$REPO_DIR/scripts/compute_branch_release_network.sh" "${DEFAULTNETWORK}")
export DEFAULT_RELEASE_NETWORK

RPMTMP=$(mktemp -d 2>/dev/null || mktemp -d -t "rpmtmp")
trap 'rm -rf $RPMTMP' 0

TEMPDIR=$(mktemp -d)
trap 'rm -rf $TEMPDIR' 0
< "$REPO_DIR/installer/rpm/algorand.spec" \
    sed -e "s,@PKG_NAME@,${PKG_NAME:-algorand}," \
        -e "s,@VER@,${FULLVERSION:-6.6.6}," \
    > "$TEMPDIR/algorand.spec"

rpmbuild --buildroot "$HOME/foo" --define "_rpmdir $RPMTMP" --define "RELEASE_GENESIS_PROCESS x$RELEASE_GENESIS_PROCESS" --define "LICENSE_FILE ./COPYING" -bb "$TEMPDIR/algorand.spec"

mkdir -p "$REPO_DIR/tmp/node_pkgs/$OS_TYPE/$ARCH/pkg"
cp -p "$RPMTMP"/*/*.rpm "$REPO_DIR/tmp/node_pkgs/$OS_TYPE/$ARCH/pkg"

