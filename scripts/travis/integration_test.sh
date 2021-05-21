#!/usr/bin/env bash

# integration_test.sh - Performs pre-build checks on the branch
#
# Syntax:   integration_test.sh
#
# Usage:    Can be used by either Travis or an ephermal build machine
#
# Examples: scripts/travis/integration_test.sh
set -e

ALGORAND_DEADLOCK=enable
export ALGORAND_DEADLOCK

SCRIPTPATH="$( cd "$(dirname "$0")" ; pwd -P )"

export BUILD_TYPE="integration"


if [ "${USER}" = "travis" ]; then
    # we're running on a travis machine
    "${SCRIPTPATH}/travis_wait.sh" 120 "${SCRIPTPATH}/build.sh" --make_debug
    "${SCRIPTPATH}/travis_wait.sh" 120 "${SCRIPTPATH}/test.sh"
else
    # we're running on an ephermal build machine
    "${SCRIPTPATH}/build.sh" --make_debug
    "${SCRIPTPATH}/test.sh"
fi

echo "Integration test completed successfully"
