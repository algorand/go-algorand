#!/usr/bin/env bash

# codegen_verification.sh - Run the auto-code generation and verify it matches current branch content.
#
# Syntax:   codegen_verification.sh
#
# Usage:    Can be used by either Travis or an ephemeral build machine
#
# Examples: scripts/travis/codegen_verification.sh
set -e

ALGORAND_DEADLOCK=enable
export ALGORAND_DEADLOCK
GOPATH=$(go env GOPATH)
export GOPATH
SCRIPTPATH="$( cd "$(dirname "$0")" ; pwd -P )"

# Force re-evaluation of genesis files to see if source files changed w/o running make
touch gen/generate.go

make build

"${SCRIPTPATH}"/../buildtools/install_buildtools.sh

make gen SHORT_PART_PERIOD=1

echo "Running check_license..."
./scripts/check_license.sh

echo "Rebuild swagger.json files"
make rebuild_kmd_swagger

echo "Regenerate for stringer et el."
make generate

echo "Running fixcheck"
"$GOPATH"/bin/algofix -error */

echo "Running modernize checks"
make modernize

echo "Running expect linter"
make expectlint

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

echo Checking Tidiness...
make tidy
if [[ -n $(git status --porcelain) ]]; then
   echo Dirty after go mod tidy - did you forget to run make tidy?
   git status -s
   git --no-pager diff
   exit 1
else
   echo All tidy
fi

# test binary compatibility
"${SCRIPTPATH}/../../test/platform/test_linux_amd64_compatibility.sh"
