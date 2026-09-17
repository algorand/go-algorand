#!/usr/bin/env bash

# Print the go-algorand packages that coverage is measured for, comma separated,
# for "go test -coverpkg".
#
# Excluded are the e2e test tree, the command line programs and tools, and
# packages that exist only to support other packages' tests. Keep this in sync
# with the ignore list in .codecov.yml: a package measured here but ignored
# there, or the other way round, silently changes which files the coverage
# total is computed over.

set -eo pipefail

go list ./... |
    grep -E -v '/go-algorand/(test|debug|cmd|config/defaultsGenerator|tools)' |
    grep -E -v '(test|testing|mock|mocks)$' |
    paste -sd ',' -
