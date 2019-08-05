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
    warningCount=$($GOPATH/bin/golint `go list ./... | grep -v /vendor/ | grep -v /test/e2e-go/` | wc -l)
    if [ $warningCount -eq 0 ]; then
        return 0
    fi

    echo >&2 "golint must be clean.  Please run the following to list issues:"
    echo >&2 " make lint"

    return 1
}

export GOPATH=$(go env GOPATH)
export GO111MODULE=on

echo "Building libsodium-fork..."
make crypto/lib/libsodium.a

echo "Running go vet..."
go vet `go list ./... | grep -v /test/e2e-go/`

echo "Running gofmt..."
runGoFmt

echo "Running golint..."
runGoLint

