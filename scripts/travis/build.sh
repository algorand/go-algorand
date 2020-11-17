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
set -x

CONFIGURE_SUCCESS=false

SCRIPTPATH="$( cd "$(dirname "$0")" ; pwd -P )"

OS=$("${SCRIPTPATH}/../ostype.sh")
ARCH=$("${SCRIPTPATH}/../archtype.sh")
# Use go build version specified by get_golang_version.sh
if ! GOLANG_VERSION=$("${SCRIPTPATH}/../check_golang_version.sh")
then
    echo "${GOLANG_VERSION}"
    exit 1
fi

curl -sL -o ~/gimme https://raw.githubusercontent.com/travis-ci/gimme/master/gimme
chmod +x ~/gimme
eval $(~/gimme "${GOLANG_VERSION}")

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

if [ "${OS}-${ARCH}" = "linux-arm" ] || [ "${OS}-${ARCH}" = "windows-amd64" ]; then
    # for arm, build just the basic distro
    # for windows, we still have some issues with the enlistment checking, so we'll make it simple for now.
    MAKE_DEBUG_OPTION=""
fi

if [ "${MAKE_DEBUG_OPTION}" != "" ]; then
    # Force re-generation of msgpack encoders/decoders with msgp.  If this re-generated code
    # does not match the checked-in code, some structs may have been added or updated without
    # refreshing the generated codecs.  The enlistment check below will error out, if so.
    # we want to have that only on system where we have some debugging abilities. Platforms that do not support
    # debugging ( i.e. arm ) are also usually under powered and making this extra step
    # would be very costly there.
    make msgp
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
