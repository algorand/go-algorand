#!/bin/bash

set -ex

echo "Building RPM package"

REPO_DIR=$(pwd)
ARCH=$(./scripts/archtype.sh)
OS_TYPE=$(./scripts/ostype.sh)
FULLVERSION=${VERSION:-$(./scripts/compute_build_number.sh -f)}
BRANCH=${BRANCH:-$(git rev-parse --abbrev-ref HEAD)}
CHANNEL=${CHANNEL:-$(./scripts/compute_branch_channel.sh "$BRANCH")}
ALGO_BIN="$REPO_DIR/tmp/node_pkgs/$OS_TYPE/$ARCH/$CHANNEL/$OS_TYPE-$ARCH/bin"
# TODO: Should there be a default network?
DEFAULTNETWORK=devnet
DEFAULT_RELEASE_NETWORK=$(./scripts/compute_branch_release_network.sh "$DEFAULTNETWORK")
PKG_NAME=$(./scripts/compute_package_name.sh "${CHANNEL:-stable}")

# The following need to be exported for use in ./go-algorand/installer/rpm/algorand.spec.
export DEFAULT_NETWORK
export DEFAULT_RELEASE_NETWORK
export REPO_DIR
export ALGO_BIN

RPMTMP=$(mktemp -d 2>/dev/null || mktemp -d -t "rpmtmp")
trap 'rm -rf $RPMTMP' 0

TEMPDIR=$(mktemp -d)
trap 'rm -rf $TEMPDIR' 0
< "./installer/rpm/algorand.spec" \
    sed -e "s,@PKG_NAME@,$PKG_NAME," \
        -e "s,@VER@,$FULLVERSION," \
    > "$TEMPDIR/algorand.spec"

rpmbuild --buildroot "$HOME/foo" --define "_rpmdir $RPMTMP" --define "RELEASE_GENESIS_PROCESS x$RELEASE_GENESIS_PROCESS" --define "LICENSE_FILE ./COPYING" -bb "$TEMPDIR/algorand.spec"

cp -p "$RPMTMP"/*/*.rpm "./tmp/node_pkgs/$OS_TYPE/$ARCH"

