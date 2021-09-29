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

# $1 - Message
LAST_DURATION=$SECONDS
function duration() {
  ELAPSED=$((SECONDS - $LAST_DURATION))
  printf "Duration: '%s' - %02dh:%02dm:%02ds\n" "$1" $(($ELAPSED/3600)) $(($ELAPSED%3600/60)) $(($ELAPSED%60))
  LAST_DURATION=$SECONDS
}

CONFIGURE_SUCCESS=false

SCRIPTPATH="$( cd "$(dirname "$0")" ; pwd -P )"

OS=$("${SCRIPTPATH}/../ostype.sh")
ARCH=$("${SCRIPTPATH}/../archtype.sh")

# Get the go build version.
if [ -z "${SKIP_GO_INSTALLATION}" ]; then
  GOLANG_VERSION=$(./scripts/get_golang_version.sh)
  GIMME_PATH="${GIMME_INSTALL_DIR:-${HOME}}/gimme"
  curl -sL -o "${GIMME_PATH}" https://raw.githubusercontent.com/travis-ci/gimme/master/gimme
  chmod +x "${GIMME_PATH}"
  eval "$("${GIMME_PATH}" "${GOLANG_VERSION}")"
fi

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
duration "configure_dev.sh"

if [ "${CONFIGURE_SUCCESS}" = "false" ]; then
    echo "Attempted to configure the environment multiple times, and failed. See above logs for details."
    exit 1
fi

set -e
scripts/travis/before_build.sh
duration "before_build.sh"

if [ "${OS}-${ARCH}" = "linux-arm" ] || [ "${OS}-${ARCH}" = "windows-amd64" ]; then
    # for arm, build just the basic distro
    # for windows, we still have some issues with the enlistment checking, so we'll make it simple for now.
    MAKE_DEBUG_OPTION=""
fi

if [ "${MAKE_DEBUG_OPTION}" != "" ]; then
    make build build-race
    duration "make build build-race"
else
    make build
    duration "make build"
fi
