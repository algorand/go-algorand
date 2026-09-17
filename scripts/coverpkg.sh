#!/usr/bin/env bash

# Print the packages coverage is measured for, comma separated, for -coverpkg.
#
# Excluded are the e2e tree, the command line programs and tools, and packages
# that only support other packages' tests. Keep in sync with the ignore list in
# .codecov.yml, which decides the same thing for the report.

set -eo pipefail

go list ./... |
    grep -E -v '/go-algorand/(test|debug|cmd|config/defaultsGenerator|tools)' |
    grep -E -v '(test|testing|mock|mocks)$' |
    paste -sd ',' -
