#!/usr/bin/env bash

set -ex

OS_TYPE="$1"
ARCH_TYPE="$2"
ARCH_BIT="$3"
VERSION="$4"
WORKDIR="$5"

if [ -z "$OS_TYPE" ] || [ -z "$ARCH_TYPE" ] || [ -z "$ARCH_BIT" ] || [ -z "$VERSION" ] || [ -z "$WORKDIR" ]; then
    echo "OS=$OS, ARCH_TYPE=$ARCH_TYPE, ARCH_BIT=$ARCH_BIT, VERSION=$VERSION and WORKDIR=$WORKDIR variables must be defined."
    exit 1
fi

echo
date "+build_release begin TEST stage %Y%m%d_%H%M%S"
echo

# Just for testing...
VERSION=2.0.5

export OS_TYPE
export ARCH_TYPE
export ARCH_BIT
export VERSION
export WORKDIR

MULE_TEST_DIR="$WORKDIR/scripts/release/mule/test"
export MULE_TEST_DIR

RPM_DIR="$MULE_TEST_DIR/$OS_TYPE/$ARCH_TYPE/rpm"
export RPM_DIR

#SHA=$(git rev-parse HEAD)
SHA=8b0be452
export SHA

#BRANCH=$(git rev-parse --abbrev-ref HEAD)
BRANCH=rel/stable
export BRANCH

#CHANNEL=$("$WORKDIR/scripts/compute_branch_channel.sh" "$BRANCH")
CHANNEL=stable

export CHANNEL

"$MULE_TEST_DIR/util/mule.sh"
"$RPM_DIR/test/goal.sh"
"$MULE_TEST_DIR/util/test_package.sh"

echo
date "+build_release end TEST stage %Y%m%d_%H%M%S"
echo

