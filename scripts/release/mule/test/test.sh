#!/usr/bin/env bash

set -ex

export PKG_TYPE="$1"
ARCH_BIT=$(uname -m)
export ARCH_BIT
ARCH_TYPE=$(./scripts/archtype.sh)
export ARCH_TYPE
OS_TYPE=$(./scripts/ostype.sh)
export OS_TYPE

export BRANCH=${BRANCH:-$(git rev-parse --abbrev-ref HEAD)}
export CHANNEL=${CHANNEL:-$(./scripts/compute_branch_channel.sh "$BRANCH")}
export NETWORK=${NETWORK:-$(./scripts/compute_branch_network.sh "$BRANCH")}
export SHA=${SHA:-$(git rev-parse HEAD)}
export VERSION=${VERSION:-$(./scripts/compute_build_number.sh -f)}

#if ! $USE_CACHE
#then
#    mule -f package-test.yaml "package-test-setup-$PKG_TYPE"
#    agent: deb
#    bucketName: algorand-staging
#    objectName: releases/$CHANNEL/$VERSION/algorand_${CHANNEL}_${OS_TYPE}-${ARCH_TYPE}_${VERSION}.deb
#    outputDir: /projects/go-algorand/tmp/node_pkgs/${OS_TYPE}/${ARCH_TYPE}
#
#    name: rpm
#    bucketName: algorand-staging
#    objectName: releases/$CHANNEL/$VERSION/algorand-${VERSION}-1.${ARCH_BIT}.rpm
#    outputDir: /projects/go-algorand/tmp/node_pkgs/${OS_TYPE}/${ARCH_TYPE}
#fi

./scripts/release/mule/test/tests/run_tests
#if [[ "$ARCH_TYPE" =~ "arm" ]]
#then
#    ./scripts/release/mule/test/tests/run_tests -b "$BRANCH" -c "$CHANNEL" -h "$SHA" -n "$NETWORK" -r "$VERSION"
#else
#    ./scripts/release/mule/test/util/test_package.sh
#fi

