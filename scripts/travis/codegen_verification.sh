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

# Get the go build version.
GOLANG_VERSION=$(./scripts/get_golang_version.sh)

eval "$(~/gimme "${GOLANG_VERSION}")"

"${SCRIPTPATH}"/../buildtools/install_buildtools.sh

make gen SHORT_PART_PERIOD=1

function runGoFmt() {
    unformatted=$(gofmt -l .)
    [ -z "$unformatted" ] && return 0

    # Some files are not gofmt'd. Print message and fail.

    echo >&2 "Go files must be formatted with gofmt. Please run:"
    for fn in $unformatted; do
        echo >&2 "  gofmt -w $PWD/$fn"
    done

    return 1
}

function runGoLint() {
    "$GOPATH"/bin/golangci-lint run -c .golangci.yml > temp-golangci-lint-results.txt
    echo "golangci-lint finished with exit code: {$?}"
    echo "START OF temp-golangci-lint-results.txt"
    cat temp-golangci-lint-results.txt
    echo "END OF temp-golangci-lint-results.txt"
    warningCount=$(cat temp-golangci-lint-results.txt | wc -l | tr -d ' ')
    echo "warningCount is: ${warningCount}"
    if [ "${warningCount}" = "0" ]; then
        echo "Exiting golangci-lint successfully because warningCount = 0"
        return 0
    fi
    echo "Golangci-lint errored out:"
    cat temp-golangci-lint-results.txt >&2
    echo >&2 "golangci-lint must be clean.  Please see above list issues(${warningCount}):"
    echo >&2 "To replicate please run: make lint"

    exit 1
}

echo "Running gofmt..."
# runGoFmt # UNCOMMENT

echo "Running golangci-lint..."
#runGoLint
set -x
"$GOPATH"/bin/golangci-lint --version

"$GOPATH"/bin/golangci-lint run -c .golangci.yml

"Exiting because runGoLint didn't work properly." # REMOVE
set +x
exit 1 # REMOVE

echo "Running check_license..."
./scripts/check_license.sh

echo "Rebuild swagger.json files"
make rebuild_swagger

echo "Regenerate config files"
go generate ./config

echo "Running fixcheck"
GOPATH=$(go env GOPATH)
"$GOPATH"/bin/algofix -error */

echo "Updating TEAL Specs"
touch data/transactions/logic/fields_string.go # ensure rebuild
make -C data/transactions/logic

echo "Regenerate REST server"
touch daemon/algod/api/algod.oas2.json
make -C daemon/algod/api generate

echo "Regenerate msgp files"
make msgp

echo Checking Enlistment...
if [[ -n $(git status --porcelain) ]]; then
   echo Enlistment is dirty - did you forget to run make?
   git status -s
   git --no-pager diff
   exit 1
else
   echo Enlistment is clean
fi

# test binary compatibility
"${SCRIPTPATH}/../../test/platform/test_linux_amd64_compatibility.sh"
