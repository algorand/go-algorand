#!/usr/bin/env bash

# turn off exit on error
set +e

CONFIGURE_SUCCESS=false

# travis sometimes fail to download a dependency. trying multiple times might help.
for (( attempt=1; attempt<=5; attempt++ ))
do
    scripts/travis/configure_dev.sh
    ERR=$?
    if [ "$?" == "0" ]; then
        CONFIGURE_SUCCESS=true
        break
    fi
    echo "Running configure_dev.sh resulted in exit code ${ERR}; retrying in 3 seconds"
    sleep 3s
done

if [ "${CONFIGURE_SUCCESS}" = "false" ]; then
    echo "Attempted to configure the environment multiple times, and failed. See above logs for details."
    exit 1
fi

set -e
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
