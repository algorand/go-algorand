#!/usr/bin/env bash

PKG_TYPE="$1"

# Just for testing...
VERSION=2.0.5

#SHA=$(git rev-parse HEAD)
SHA=8b0be452

#BRANCH=$(git rev-parse --abbrev-ref HEAD)
BRANCH=rel/stable

#CHANNEL=$("$WORKDIR/scripts/compute_branch_channel.sh" "$BRANCH")
CHANNEL=stable

# Needed by mule.yaml file and ./util/test_package.
#export ARCH_BIT
export CHANNEL
#export OS_TYPE
#export VERSION
export BRANCH
export SHA

# To contain the downloaded packages from staging.
mkdir -p "$WORKDIR/pkg"

mule -f package-test.yaml "package-test-setup-$PKG_TYPE"
"$WORKDIR/scripts/release/mule/test/util/test_package.sh" "$PKG_TYPE"

