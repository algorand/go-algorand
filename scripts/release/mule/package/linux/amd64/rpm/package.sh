#!/bin/bash

set -ex

echo "Building RPM package"

export REPO_DIR=/projects/go-algorand
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

# TODO: Don't hardcode this path!
# Will change to something like:
# "$REPO_DIR/tmp/node_pkgs/$OS_TYPE/$ARCH/pkg"
mkdir -p "$REPO_DIR/tmp/node_pkgs/linux/amd64/pkg"
cp -p "$RPMTMP"/*/*.rpm "$REPO_DIR/tmp/node_pkgs/linux/amd64/pkg"

