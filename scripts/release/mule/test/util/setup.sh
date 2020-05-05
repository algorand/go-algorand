#!/usr/bin/env bash

PKG_TYPE="$1"

BRANCH=${BRANCH:-$(git rev-parse --abbrev-ref HEAD)}
export BRANCH
CHANNEL=${CHANNEL:-$("$WORKDIR/scripts/compute_branch_channel.sh" "$BRANCH")}
export CHANNEL
SHA=${SHA:-$(git rev-parse HEAD)}
export SHA
VERSION=${VERSION:-$FULLVERSION}
export VERSION

# To contain the downloaded packages from staging.
mkdir -p "$WORKDIR/pkg"

mule -f package-test.yaml "package-test-setup-$PKG_TYPE"
"$WORKDIR/scripts/release/mule/test/util/test_package.sh" "$PKG_TYPE"

