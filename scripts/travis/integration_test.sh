#!/usr/bin/env bash

# integration_test.sh - Performs pre-build checks on the branch
#
# Syntax:   integration_test.sh
#
# Usage:    Can be used by either Travis or an ephermal build machine
#
# Examples: scripts/travis/integration_test.sh
set -e

SCRIPTPATH="$( cd "$(dirname "$0")" ; pwd -P )"
export BUILD_TYPE="integration"
if [ "${USER}" = "travis" ]; then
    # we're running on a travis machine
    ${SCRIPTPATH}/build.sh
    ${SCRIPTPATH}/travis_wait.sh 90 ${SCRIPTPATH}/test.sh
else
    # we're running on an ephermal build machine
    ${SCRIPTPATH}/build.sh
    ${SCRIPTPATH}/test.sh
fi
