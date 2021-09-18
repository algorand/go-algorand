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
SCRIPTPATH="$( cd "$(dirname "$0")" ; pwd -P )"

"${SCRIPTPATH}/build.sh" --make_debug
"${SCRIPTPATH}/test.sh"
