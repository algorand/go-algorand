#!/usr/bin/env bash

# before_build.sh - Performs pre-build checks on the branch
#
# Syntax:   before_build.sh
#
# Usage:    Should only be used by Travis
#
# Examples: scripts/travis/before_build.sh

set -e

if $CIRCLECI; then
  GOPATH=/home/circleci/.go_workspace;
else
  GOPATH=$(go env GOPATH)
fi

export GOPATH
export GO111MODULE=on

SCRIPTPATH="$( cd "$(dirname "$0")" ; pwd -P )"
OS=$("${SCRIPTPATH}"/../ostype.sh)
ARCH=$("${SCRIPTPATH}"/../archtype.sh)

echo "Building libsodium-fork..."
make crypto/libs/${OS}/${ARCH}/lib/libsodium.a


