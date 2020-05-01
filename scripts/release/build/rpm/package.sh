#!/usr/bin/env bash

set -ex

echo "Building RPM package"

cd "$(dirname "$0")"/..

REPO_DIR=${HOME}/subhome/go/src/github.com/algorand/go-algorand
export REPO_DIR
DEFAULT_RELEASE_NETWORK=$("$REPO_DIR/scripts/compute_branch_release_network.sh" "${DEFAULTNETWORK}")
export DEFAULT_RELEASE_NETWORK
DEFAULTNETWORK=devnet
export DEFAULT_NETWORK
ALGO_BIN="$HOME/subhome/go/bin"
export ALGO_BIN

RPMTMP=$(mktemp -d 2>/dev/null || mktemp -d -t "rpmtmp")
trap 'rm -rf ${RPMTMP}' 0

BRANCH=$("$REPO_DIR/scripts/compute_branch.sh")
CHANNEL=$("$REPO_DIR/scripts/compute_branch_channel.sh" "$BRANCH")
PKG_NAME=$("$REPO_DIR/scripts/compute_package_name.sh" "${CHANNEL:-stable}")

TEMPDIR=$(mktemp -d)
trap 'rm -rf $TEMPDIR' 0
< "$REPO_DIR/installer/rpm/algorand.spec" \
    sed -e "s,@PKG_NAME@,${PKG_NAME:-algorand}," \
        -e "s,@VER@,$FULLVERSION," \
    > "$TEMPDIR/algorand.spec"

rpmbuild --define "_rpmdir ${RPMTMP}" --define "RELEASE_GENESIS_PROCESS x${RELEASE_GENESIS_PROCESS}" --define "LICENSE_FILE $REPO_DIR/COPYING" -bb "${TEMPDIR}/algorand.spec"

mkdir -p /root/subhome/node_pkg
cp -p "${RPMTMP}"/*/*.rpm /root/subhome/node_pkg

