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

REPO_DIR="$WORKDIR"
FULLVERSION=$("$REPO_DIR/scripts/compute_build_number.sh" -f)
BRANCH=$("$REPO_DIR/scripts/compute_branch.sh")
CHANNEL=$("$REPO_DIR/scripts/compute_branch_channel.sh" "$BRANCH")
ALGO_BIN="$REPO_DIR/tmp/node_pkgs/$OS_TYPE/$ARCH/$CHANNEL/$OS_TYPE-$ARCH/bin"
# TODO: Should there be a default network?
DEFAULTNETWORK=devnet
DEFAULT_RELEASE_NETWORK=$("$REPO_DIR/scripts/compute_branch_release_network.sh" "${DEFAULTNETWORK}")

# The following need to be exported for use in ./go-algorand/installer/rpm/algorand.spec.
export DEFAULT_NETWORK
export DEFAULT_RELEASE_NETWORK
export REPO_DIR
export ALGO_BIN

RPMTMP=$(mktemp -d 2>/dev/null || mktemp -d -t "rpmtmp")
trap 'rm -rf $RPMTMP' 0

TEMPDIR=$(mktemp -d)
trap 'rm -rf $TEMPDIR' 0
< "$REPO_DIR/installer/rpm/algorand.spec" \
    sed -e "s,@PKG_NAME@,${PKG_NAME:-algorand}," \
        -e "s,@VER@,$FULLVERSION," \
    > "$TEMPDIR/algorand.spec"

rpmbuild --buildroot "$HOME/foo" --define "_rpmdir $RPMTMP" --define "RELEASE_GENESIS_PROCESS x$RELEASE_GENESIS_PROCESS" --define "LICENSE_FILE ./COPYING" -bb "$TEMPDIR/algorand.spec"

mkdir -p "$REPO_DIR/tmp/node_pkgs/$OS_TYPE/$ARCH/pkg"
cp -p "$RPMTMP"/*/*.rpm "$REPO_DIR/tmp/node_pkgs/$OS_TYPE/$ARCH/pkg"

