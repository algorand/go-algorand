#!/usr/bin/env bash

# There are two primary use cases for this script.
#
# 1. Making sure that the builds for production are using the exact version specified in `get_golang_version.sh` (in $BUILD).
#    This is the default case.
#
# 2. Ensuring that an end user that is building locally is using a version of go that will enable a successful compilation.
#    In this case, we specify a minimum version that we know is enough to compile.
#    This is the "dev" case.
#    See `./scripts/{configure_dev,configure_dev-deps}.sh`.

set -eo pipefail

read -ra GOLANG_VERSIONS <<< "$(./scripts/get_golang_version.sh all)"
BUILD_VERSION="${GOLANG_VERSIONS[0]}"
MIN_VERSION="${GOLANG_VERSIONS[1]}"

# Get the field "go1.1.1" and then remove the "go" prefix.
SYSTEM_GOLANG_VERSION=$(go version | awk '{ gsub(/go/, "", $3); print $3 }')

# https://golang.org/doc/go1.11#modules
if [[ "$(printf '%s\n' ${SYSTEM_GOLANG_VERSION} 1.11 | sort -V | head -n1)" != "1.11" ]]; then
    echo "[$0] ERROR: The version of go on the system (${SYSTEM_GOLANG_VERSION}) is too old and does not support go modules. Please update to at least 1.11."
    exit 1
fi

if [[ "$(printf '%s\n' "$SYSTEM_GOLANG_VERSION" "$MIN_VERSION" | sort -V | head -n1)" != "$MIN_VERSION" ]]; then
    # We are below the minimum version
    if [ "$1" == "dev" ]; then
        echo "[$0] WARNING: The version of go on the system (${SYSTEM_GOLANG_VERSION}) is below the recommended minimum version (${MIN_VERSION}) and therefore may not build correctly."
        echo "[$0] Please update to at least ${MIN_VERSION}"
    elif [ "$1" == "build" ]; then
        echo "[$0] ERROR: The version of go on the system (${SYSTEM_GOLANG_VERSION}) is below the necessary minimum version (${MIN_VERSION}) and therefore will not build correctly."
        exit 1
    fi
else
    # Check to make sure that it matches what is specified in `go.mod`.
    GOMOD_TOOL_VERSION=$(go mod edit -print | awk '$1 == "toolchain" {sub(/^go/, "", $2); print $2}')

    if [[ "${BUILD_VERSION}" != "${GOMOD_TOOL_VERSION}" ]]; then
        echo "[$0] ERROR: go version mismatch, go mod tool version ${GOMOD_TOOL_VERSION} does not match required version ${BUILD_VERSION}"
        exit 1
    else
        echo "${BUILD_VERSION}"
    fi
fi

