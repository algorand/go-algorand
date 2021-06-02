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

SCRIPTPATH="$( cd "$(dirname "$0")" ; pwd -P )"
OS=$("${SCRIPTPATH}/../ostype.sh")
ARCH=$("${SCRIPTPATH}/../archtype.sh")

# Get the go build version.
GOLANG_VERSION=$(./scripts/get_golang_version.sh)

curl -sL -o ~/gimme https://raw.githubusercontent.com/travis-ci/gimme/master/gimme
chmod +x ~/gimme
eval "$(~/gimme "${GOLANG_VERSION}")"

"${SCRIPTPATH}/../buildtools/install_buildtools.sh"

if [ "${USER}" = "travis" ]; then
    # we're running on a travis machine
    "${SCRIPTPATH}/travis_wait.sh" 120 "${SCRIPTPATH}/build.sh" --make_debug
    "${SCRIPTPATH}/travis_wait.sh" 120 "${SCRIPTPATH}/test.sh"
else
    # we're running on an ephermal build machine
    "${SCRIPTPATH}/build.sh" --make_debug
    "${SCRIPTPATH}/test.sh"
fi
