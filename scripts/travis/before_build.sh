#!/usr/bin/env bash

# before_build.sh - Performs pre-build checks on the branch
#
# Syntax:   before_build.sh
#
# Usage:    Should only be used by Travis
#
# Examples: scripts/travis/before_build.sh

set -e

GOPATH=$(go env GOPATH)
export GOPATH

SCRIPTPATH="$( cd "$(dirname "$0")" ; pwd -P )"
OS=$("${SCRIPTPATH}"/../ostype.sh)
ARCH=$("${SCRIPTPATH}"/../archtype.sh)

if [ ! -f crypto/libs/${OS}/${ARCH}/lib/libsodium.a ]; then
  echo "Building libsodium-fork..."
  make crypto/libs/${OS}/${ARCH}/lib/libsodium.a
fi


