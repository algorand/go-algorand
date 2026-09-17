#!/usr/bin/env bash

# Merge raw Go coverage data (GOCOVERDIR format) into a text coverage profile.
#
# With -coverpkg, "go test -coverprofile" writes each block once per test binary
# and does not combine them. Consumers that do not sum duplicates, Codecov among
# them, then report wrong per-file coverage, including well covered files as 0%.
# "go tool covdata" merges correctly.
#
# Usage: merge_coverage.sh <raw-covdata-dir> <output-profile>

set -eo pipefail

RAW="$1"
OUT="$2"

if [[ -z "$RAW" || -z "$OUT" ]]; then
    echo "usage: $0 <raw-covdata-dir> <output-profile>" >&2
    exit 1
fi

# Tests may have failed before writing anything; that is the caller's problem.
if ! ls "$RAW"/covmeta.* > /dev/null 2>&1; then
    echo "$0: no coverage data found in $RAW, nothing to merge" >&2
    exit 0
fi

MERGED=$(mktemp -d)
trap 'rm -rf "$MERGED"' EXIT

# -pcombine collapses the per-binary metadata into one pair of files.
go tool covdata merge -i="$RAW" -o="$MERGED" -pcombine
go tool covdata textfmt -i="$MERGED" -o="$OUT"
