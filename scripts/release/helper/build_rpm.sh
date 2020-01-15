#!/bin/bash -e

# build_rpm.sh - Build a .deb package for one platform.
#
# Syntax:   build_rpm.sh <output directory>
#
# Examples: scripts/build_rpm.sh /tmp

if [ ! "$#" -eq 1 ]; then
    echo "Syntax: build_rpm.sh <output directory>"
    exit 1
fi

set -x

OUTDIR="$1"

GOPATH=$(go env GOPATH)
export GOPATH

cd "$(dirname "$0")"/..
#export REPO_DIR=$(pwd -P)
export REPO_DIR=$HOME/go/src/github.com/algorand/go-algorand

echo "Building RPM package"

#env GOOS="${OS}" GOARCH="${ARCH}" "$REPO_DIR/scripts/build_prod.sh"
env GOOS="${OS}" GOARCH="${ARCH}" make build --directory "${REPO_DIR}"

VER=$("$REPO_DIR/scripts/compute_build_number.sh" -f)

if [ "${DEFAULTNETWORK}" = "" ]; then
    DEFAULTNETWORK=$("$REPO_DIR/scripts/compute_branch_network.sh")
    export DEFAULTNETWORK
fi

DEFAULT_RELEASE_NETWORK=$("$REPO_DIR/scripts/compute_branch_release_network.sh" "${DEFAULTNETWORK}")
export DEFAULT_RELEASE_NETWORK

TEMPDIR=$(mktemp -d)
trap 'rm -rf $TEMPDIR' 0
< "$REPO_DIR/installer/rpm/algorand.spec" sed -e s,@VER@,"${VER}", > "${TEMPDIR}/algorand.spec"

rpmbuild --define "_rpmdir ${OUTDIR}" --define "RELEASE_GENESIS_PROCESS x${RELEASE_GENESIS_PROCESS}" --define "LICENSE_FILE $REPO_DIR/COPYING" -bb "${TEMPDIR}/algorand.spec"

