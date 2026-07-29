#!/usr/bin/env bash

# Run the tools/x-repo-types cross-repo type comparison against a local
# go-algorand-sdk checkout rather than the SDK's published main branch.
#
# The "Test tools modules" CI job always compares against upstream main, so
# when a go-algorand type change requires a matching SDK change there is no way
# to make that job green until the SDK side has landed. This script points the
# comparison at a working copy instead, so the SDK edits can be developed and
# verified first.
#
# Usage:
#   ./scripts/test_x_repo_types.sh [case]
#
# "case" is a TestCrossRepoTypes subtest name, e.g. goal-v-sdk-eval-delta. With
# no argument, every case runs (several minutes). Set SDK_DIR to override the
# default sibling checkout location.

set -eo pipefail

REPO_ROOT=$(git rev-parse --show-toplevel)
XRT_DIR="$REPO_ROOT/tools/x-repo-types"
SDK_DIR=${SDK_DIR:-"$REPO_ROOT/../go-algorand-sdk"}

if [ ! -d "$SDK_DIR" ]; then
    echo "[$0] ERROR: no go-algorand-sdk checkout at ${SDK_DIR}. Set SDK_DIR to point at one."
    exit 1
fi
# go.mod replace directives need an absolute, symlink-free path.
SDK_DIR=$(cd "$SDK_DIR" && pwd -P)

RUN="TestCrossRepoTypes"
if [ -n "$1" ]; then
    RUN="TestCrossRepoTypes/$1"
fi

cd "$XRT_DIR"

# The test "go get"s each package under comparison, rewriting go.mod and go.sum
# as it goes, so keep pristine copies and put them back however we exit.
BACKUP=$(mktemp -d)
restore() {
    cp "$BACKUP/go.mod" "$BACKUP/go.sum" "$XRT_DIR"
    rm -rf "$BACKUP"
}
cp go.mod go.sum "$BACKUP"
trap restore EXIT

go mod edit -replace "github.com/algorand/go-algorand-sdk/v2=$SDK_DIR"

SDK_HEAD=$(git -C "$SDK_DIR" rev-parse --short HEAD 2>/dev/null || echo "not a git checkout")
echo "[$0] comparing against SDK at ${SDK_DIR} (${SDK_HEAD})"

go test -v -count=1 -run "$RUN" ./
