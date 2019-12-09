#!/usr/bin/env bash

# build.sh - Performs a build on the branch
#
# Syntax:   build.sh
#
# Usage:    Can be used by either Travis or an ephermal build machine
#
# Examples: scripts/travis/build.sh

MAKE_DEBUG_OPTION=""
while [ "$1" != "" ]; do
    case "$1" in
        --make_debug)
            shift
            MAKE_DEBUG_OPTION="1"
            ;;
        *)
            echo "Unknown option" "$1"
            exit 1
            ;;
    esac
    shift
done


# turn off exit on error
set +e

CONFIGURE_SUCCESS=false

SCRIPTPATH="$( cd "$(dirname "$0")" ; pwd -P )"

OS=$("${SCRIPTPATH}/../ostype.sh")
ARCH=$("${SCRIPTPATH}/../archtype.sh")

# travis sometimes fail to download a dependency. trying multiple times might help.
for (( attempt=1; attempt<=5; attempt++ ))
do
    scripts/travis/configure_dev.sh
    ERR=$?
    if [ "${ERR}" == "0" ]; then
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

# Force re-generation of msgpack encoders/decoders with msgp.  If this re-generated code
# does not match the checked-in code, some structs may have been added or updated without
# refreshing the generated codecs.  The enlistment check below will error out, if so.
make msgp

if [ "${OS}-${ARCH}" = "linux-arm" ]; then
    # for arm, build just the basic distro
    MAKE_DEBUG_OPTION=""
fi

if [ "${MAKE_DEBUG_OPTION}" != "" ]; then
    make build build-race
else
    make build
fi

echo Checking Enlistment...

if [[ -n $(git status --porcelain) ]]; then
    echo Enlistment is dirty - did you forget to run make?
    git status -s
    git diff
    exit 1
else
    echo Enlistment is clean
fi
