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

export GOPATH=$(go env GOPATH)

cd "$(dirname "$0")"/..

echo "Building RPM package"

if [ -z "${NO_BUILD}" ]; then
    env GOOS=${OS} GOARCH=${ARCH} scripts/build_prod.sh
else
    echo "already built"
    true
fi

VER=$(./scripts/compute_build_number.sh -f)

if [ "${DEFAULTNETWORK}" = "" ]; then
    export DEFAULTNETWORK=$(./scripts/compute_branch_network.sh)
fi
export DEFAULT_RELEASE_NETWORK=$(./scripts/compute_branch_release_network.sh "${DEFAULTNETWORK}")

TEMPDIR=$(mktemp -d)
trap "rm -rf $TEMPDIR" 0
cat installer/rpm/algorand.spec \
    | sed -e s,@VER@,${VER}, \
    > ${TEMPDIR}/algorand.spec

rpmbuild --define "_rpmdir ${OUTDIR}" --define "RELEASE_GENESIS_PROCESS x${RELEASE_GENESIS_PROCESS}" --define "LICENSE_FILE $(pwd)/COPYING" -bb ${TEMPDIR}/algorand.spec
