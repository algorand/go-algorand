#!/usr/bin/env bash

# build_test.sh - Performs a build & test on the branch
#
# Syntax:   build_test.sh
#
# Usage:    Can be used by either Travis or an ephermal build machine
#
# Examples: scripts/travis/build_test.sh
set -e

ALGORAND_DEADLOCK=enable
export ALGORAND_DEADLOCK

if [ "${USER}" = "travis" ]; then
    # we're running on a travis machine
    "${SCRIPTPATH}/travis_wait.sh" 120 "${SCRIPTPATH}/build.sh" --make_debug
    "${SCRIPTPATH}/../buildtools/install_buildtools.sh"
    "${SCRIPTPATH}/travis_wait.sh" 120 "${SCRIPTPATH}/test.sh"
else
    # we're running on an ephermal build machine
    "${SCRIPTPATH}/build.sh" --make_debug
    "${SCRIPTPATH}/../buildtools/install_buildtools.sh"
    "${SCRIPTPATH}/test.sh"
fi
