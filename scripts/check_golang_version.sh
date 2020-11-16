#!/usr/bin/env bash
# shellcheck disable=2072

set -eo pipefail

GOLANG_VERSION=$(./scripts/get_golang_version.sh)

# Get the field "go1.1.1" and then remove the "go" prefix.
SYSTEM_GOLANG_VERSION=$(go version | awk '{ gsub(/go/, "", $3); print $3 }')

# https://golang.org/doc/go1.11#modules
if [[ "${SYSTEM_GOLANG_VERSION}" < 1.12 ]]
then
    echo "The version of go on the system (${SYSTEM_GOLANG_VERSION}) is too old and does not support go modules. Please update to ${GOLANG_VERSION}"
    exit 1
fi

# Check to make sure that it matches what is specified in go.mod
GOMOD_VERSION=$(go mod edit -json | jq -r ".Go")
TRIMMED_GOLANG_VERSION=$(awk -F. '{ print $1 "." $2 }' <<< "${GOLANG_VERSION}")

if ! [[ "${GOLANG_VERSION}" == "${GOMOD_VERSION}" || "${TRIMMED_GOLANG_VERSION}" == "${GOMOD_VERSION}" ]]
then
    echo "go version mismatch, go mod version ${GOMOD_VERSION} does not match required version ${GOLANG_VERSION}"
    exit 1
else
    echo "${GOLANG_VERSION}"
fi

