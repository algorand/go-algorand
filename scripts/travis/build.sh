#!/usr/bin/env bash

set -e

scripts/travis/configure_dev.sh
scripts/travis/before_build.sh

# Force re-evaluation of genesis files to see if source files changed w/o running make
touch gen/generate.go

# Build regular and race-detector binaries; the race-detector binaries get
# used in test/scripts/e2e_go_tests.sh.
make build build-race

echo Checking Enlistment...

if [[ -n $(git status --porcelain) ]]; then
    echo Enlistment is dirty - did you forget to run make?
    git status -s
    exit 1
else
    echo Enlistment is clean
fi
