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

echo "Building libsodium-fork if needed..."
make libsodium


