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
GO_MOD_SUPPORT="${GOLANG_VERSIONS[2]}"

# Get the field "go1.1.1" and then remove the "go" prefix.
SYSTEM_GOLANG_VERSION=$(go version | awk '{ gsub(/go/, "", $3); print $3 }')

# https://golang.org/doc/go1.11#modules
if [[ "${SYSTEM_GOLANG_VERSION}" < "$GO_MOD_SUPPORT" ]]; then
    echo "[$0] ERROR: The version of go on the system (${SYSTEM_GOLANG_VERSION}) is too old and does not support go modules. Please update to at least ${MIN_VERSION}"
    exit 1
fi

if [ "$1" == "dev" ]; then
    if [[ "${SYSTEM_GOLANG_VERSION}" < "${MIN_VERSION}" ]]; then
        echo "[$0] WARNING: The version of go on the system (${SYSTEM_GOLANG_VERSION}) is below the recommended version (${MIN_VERSION}) and therefore may not build correctly."
        echo "[$0] Please update to at least ${MIN_VERSION}"
    fi
elif [ "$1" == "build" ]; then
    if [[ "${SYSTEM_GOLANG_VERSION}" < "${MIN_VERSION}" ]]; then
        echo "[$0] ERROR: The version of go on the system (${SYSTEM_GOLANG_VERSION}) is below the necessary version (${MIN_VERSION}) and therefore will not build correctly."
        exit 1
    fi
else
    # Check to make sure that it matches what is specified in `go.mod`.
    GOMOD_VERSION=$(go mod edit -json | jq -r ".Go")

    if [[ ! "${BUILD_VERSION}" =~ ^"${GOMOD_VERSION}" ]]; then
        echo "[$0] ERROR: go version mismatch, go mod version ${GOMOD_VERSION} does not match required version ${BUILD_VERSION}"
        exit 1
    else
        echo "${BUILD_VERSION}"
    fi
fi

