#!/bin/bash -e

# build_rpm.sh - Build a .deb package for one platform.
#
# Syntax:   build_rpm.sh <output directory>
#
# Examples: scripts/build_rpm.sh /tmp

set -ex

cd "$(dirname "$0")"/..
export GOPATH=$HOME/subhome/go
export REPO_DIR=${HOME}/subhome/go/src/github.com/algorand/go-algorand

echo "Building RPM package"

if [ "${DEFAULTNETWORK}" = "" ]; then
    DEFAULTNETWORK=$("$REPO_DIR/scripts/compute_branch_network.sh")
    export DEFAULTNETWORK
fi

DEFAULT_RELEASE_NETWORK=$("$REPO_DIR/scripts/compute_branch_release_network.sh" "${DEFAULTNETWORK}")
export DEFAULT_RELEASE_NETWORK

RPMTMP=$(mktemp -d 2>/dev/null || mktemp -d -t "rpmtmp")
trap 'rm -rf ${RPMTMP}' 0

TEMPDIR=$(mktemp -d)
trap 'rm -rf $TEMPDIR' 0
< "$REPO_DIR/installer/rpm/algorand.spec" sed -e s,@VER@,"${FULLVERSION}", > "${TEMPDIR}/algorand.spec"

#rpmbuild --define "_rpmdir ${OUTDIR}" --define "RELEASE_GENESIS_PROCESS x${RELEASE_GENESIS_PROCESS}" --define "LICENSE_FILE $REPO_DIR/COPYING" -bb "${TEMPDIR}/algorand.spec"
rpmbuild --define "_rpmdir ${RPMTMP}" --define "RELEASE_GENESIS_PROCESS x${RELEASE_GENESIS_PROCESS}" --define "LICENSE_FILE $REPO_DIR/COPYING" -bb "${TEMPDIR}/algorand.spec"

mkdir -p /root/subhome/node_pkg
cp -p "${RPMTMP}"/*/*.rpm /root/subhome/node_pkg

