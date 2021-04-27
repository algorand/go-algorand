#!/usr/bin/env bash

# before_build.sh - Performs pre-build checks on the branch
#
# Syntax:   before_build.sh
#
# Usage:    Should only be used by Travis
#
# Examples: scripts/travis/before_build.sh

set -e

function runGoFmt() {
    gofiles="$(git diff --cached --name-only --diff-filter=ACM | grep '\.go$' | grep -v ^vendor/)" || true
    [ -z "$gofiles" ] && return 0

    unformatted=$(gofmt -l $gofiles)
    [ -z "$unformatted" ] && return 0

    # Some files are not gofmt'd. Print message and fail.

    echo >&2 "Go files must be formatted with gofmt. Please run:"
    for fn in $unformatted; do
        echo >&2 "  gofmt -w $PWD/$fn"
    done

    return 1
}

function runGoLint() {
    warningCount=$("$GOPATH"/bin/golint $(GO111MODULE=off go list ./... | grep -v /vendor/ | grep -v /test/e2e-go/) | wc -l | tr -d ' ')
    if [ "${warningCount}" = "0" ]; then
        return 0
    fi

    echo >&2 "golint must be clean.  Please run the following to list issues(${warningCount}):"
    echo >&2 " make lint"

    return 1
}

GOPATH=$(go env GOPATH)
export GOPATH
export GO111MODULE=on

SCRIPTPATH="$( cd "$(dirname "$0")" ; pwd -P )"
OS=$("${SCRIPTPATH}"/../ostype.sh)
ARCH=$("${SCRIPTPATH}"/../archtype.sh)

echo "Building libsodium-fork..."
make crypto/libs/${OS}/${ARCH}/lib/libsodium.a

if [ "${BUILD_TYPE}" = "integration" ]; then
    echo "Skipping vet/gofmt/golint/license_check on integration test"
    exit 0
fi

if [ "${OS}-${ARCH}" = "linux-arm" ]; then
    echo "Skipping running 'go vet'/gofmt/golint for arm builds"
    exit 0
fi

if [ "${OS}-${ARCH}" = "windows-amd64" ]; then
     echo "Skipping running 'go vet'/gofmt/golint for windows builds"
     exit 0
fi

echo "Running go vet..."
go vet $(GO111MODULE=off go list ./... | grep -v /test/e2e-go/)

echo "Running gofmt..."
runGoFmt

echo "Running golint..."
runGoLint

echo "Running check_license..."
./scripts/check_license.sh

echo "Rebuild swagger.json files"
make rebuild_swagger
