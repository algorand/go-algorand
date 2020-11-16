#!/usr/bin/env bash

set -eo pipefail

GOLANG_VERSION=$(./scripts/get_golang_version.sh)

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

