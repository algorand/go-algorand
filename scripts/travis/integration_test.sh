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
"${SCRIPTPATH}/build_test.sh"

echo "Integration test completed successfully"
