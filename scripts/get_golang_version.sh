#!/usr/bin/env bash
# Required GOLANG Version for project specified here
GOLANG_VERSION="1.12.17"

# Check to make sure that it matches what is specified in go.mod

GOMOD_VERSION=$(awk '/^go[ \t]+[0-9]+\.[0-9]+(\.[0-9]+)?[ \t]*$/{print $2}' go.mod)
TRIMMED_GOLANG_VERSION=$(echo ${GOLANG_VERSION} |awk -F. '{ print $1 "." $2 }')

if ! [[ ${GOLANG_VERSION} == "${GOMOD_VERSION}" || ${TRIMMED_GOLANG_VERSION} == "${GOMOD_VERSION}" ]]
then
    echo "go version mismatch, go mod version ${GOMOD_VERSION} does not match required version ${GOLANG_VERSION}"
    exit 1;
else
    echo ${GOLANG_VERSION}
fi
