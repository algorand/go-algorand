#!/usr/bin/env bash

set -ex

export PKG_TYPE="$1"
ARCH_BIT=$(uname -m)
export ARCH_BIT
ARCH_TYPE=$(./scripts/archtype.sh)
export ARCH_TYPE
OS_TYPE=$(./scripts/ostype.sh)
export OS_TYPE

if [ -z "$VERSION" ]; then
    VERSION=${VERSION:-$(./scripts/compute_build_number.sh -f)}
fi
export VERSION

if [ -z "$BRANCH" ]; then
    BRANCH=${BRANCH:-$(git rev-parse --abbrev-ref HEAD)}
fi
export BRANCH

if [ -z "$CHANNEL" ]; then
    CHANNEL=${CHANNEL:-$(./scripts/compute_branch_channel.sh "$BRANCH")}
fi
export CHANNEL

if [ -z "$SHA" ]; then
    SHA=${SHA:-$(git rev-parse HEAD)}
fi
export SHA

if ! $USE_CACHE
then
    mule -f package-test.yaml "package-test-setup-$PKG_TYPE"
fi

if [[ "$ARCH_TYPE" =~ "arm" ]]
then
    ./scripts/release/mule/test/tests/run_tests -b "$BRANCH" -c "$CHANNEL" -h "$SHA" -r "$VERSION"
else
    ./scripts/release/mule/test/util/test_package.sh
fi

