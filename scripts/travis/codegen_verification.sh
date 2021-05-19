#!/usr/bin/env bash

# codegen_verification.sh - Run the auto-code generation and verify it matches current branch content.
#
# Syntax:   codegen_verification.sh
#
# Usage:    Can be used by either Travis or an ephermal build machine
#
# Examples: scripts/travis/codegen_verification.sh
set -e

ALGORAND_DEADLOCK=enable
export ALGORAND_DEADLOCK
SCRIPTPATH="$( cd "$(dirname "$0")" ; pwd -P )"

# Force re-evaluation of genesis files to see if source files changed w/o running make
touch gen/generate.go

"${SCRIPTPATH}/build.sh"

eval "$(~/gimme "${GOLANG_VERSION}")"

"${SCRIPTPATH}"/../buildtools/install_buildtools.sh

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

echo Checking Enlistment...
if [[ -n $(git status --porcelain) ]]; then
   echo Enlistment is dirty - did you forget to run make?
   git status -s
   git diff
   exit 1
else
   echo Enlistment is clean
fi
