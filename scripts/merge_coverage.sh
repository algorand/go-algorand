#!/usr/bin/env bash

# Merge raw Go coverage data (GOCOVERDIR format) into a text coverage profile.
#
# With -coverpkg, "go test -coverprofile" writes each block once per test binary
# and does not combine them. Consumers that do not sum duplicates, Codecov among
# them, then report wrong per-file coverage, including well covered files as 0%.
# "go tool covdata" merges correctly, across test partitions as well as within
# one, so CI merges every partition here and uploads a single report.
#
# Usage: merge_coverage.sh <output-profile> <covdata-dir>...

set -eo pipefail

OUT="$1"
shift || true

if [[ -z "$OUT" || $# -eq 0 ]]; then
    echo "usage: $0 <output-profile> <covdata-dir>..." >&2
    exit 1
fi

for dir in "$@"; do
    if ! ls "$dir"/covmeta.* > /dev/null 2>&1; then
        echo "$0: no coverage data in $dir" >&2
        exit 1
    fi
done

MERGED=$(mktemp -d)
trap 'rm -rf "$MERGED"' EXIT

# -pcombine collapses the per-binary metadata into a single pair of files.
go tool covdata merge -i="$(IFS=,; echo "$*")" -o="$MERGED" -pcombine
go tool covdata textfmt -i="$MERGED" -o="$OUT"
