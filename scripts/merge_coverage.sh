#!/usr/bin/env bash

# Merge raw Go coverage data into a single text coverage profile.
#
# When -coverpkg is set, "go test -coverprofile" writes each instrumented block
# once per test binary that links the package, and does not combine them. Tools
# that sum duplicate blocks (go tool cover) read such a profile correctly, but
# consumers that take the first or last occurrence instead -- Codecov among them
# -- report badly wrong per-file coverage, including files that are well covered
# showing up as 0%.
#
# Collecting raw coverage data instead ("go test -cover ... -args
# -test.gocoverdir=DIR") and merging it with "go tool covdata" avoids this: the
# resulting profile contains each block exactly once, with counts summed across
# every test binary that exercised it.
#
# Usage: merge_coverage.sh <raw-covdata-dir> <output-profile>

set -eo pipefail

RAW="$1"
OUT="$2"

if [[ -z "$RAW" || -z "$OUT" ]]; then
    echo "usage: $0 <raw-covdata-dir> <output-profile>" >&2
    exit 1
fi

# Tests may have failed before writing any coverage data. Leave it to the caller
# to decide whether that is fatal; an absent profile is not this script's error.
if ! ls "$RAW"/covmeta.* > /dev/null 2>&1; then
    echo "$0: no coverage data found in $RAW, nothing to merge" >&2
    exit 0
fi

MERGED=$(mktemp -d)
trap 'rm -rf "$MERGED"' EXIT

# -pcombine collapses the per-test-binary metadata into a single pair of files,
# which keeps the intermediate ~30x smaller than the raw data.
go tool covdata merge -i="$RAW" -o="$MERGED" -pcombine
go tool covdata textfmt -i="$MERGED" -o="$OUT"
