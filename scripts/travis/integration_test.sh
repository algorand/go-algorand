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
curl -sL -o ~/gimme https://raw.githubusercontent.com/travis-ci/gimme/master/gimme
chmod +x ~/gimme
eval $(~/gimme $("${SCRIPTPATH}/../get_golang_version.sh"))

export BUILD_TYPE="integration"
if [ "${USER}" = "travis" ]; then
    # we're running on a travis machine
    "${SCRIPTPATH}/build.sh" --make_debug
    GOPATHBIN=$(go env GOPATH)/bin
    export PATH=$PATH:$GOPATHBIN
    "${SCRIPTPATH}/travis_wait.sh" 120 "${SCRIPTPATH}/test.sh"
else
    # we're running on an ephermal build machine
    "${SCRIPTPATH}/build.sh" --make_debug
    GOPATHBIN=$(go env GOPATH)/bin
    export PATH=$PATH:$GOPATHBIN    
    "${SCRIPTPATH}/test.sh"
fi

echo "Integration test completed successfully"
