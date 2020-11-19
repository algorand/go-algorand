#!/usr/bin/env bash

# deploy_packages.sh - Script executed by Travis for 'Deploy' step, if build / tests succeed
#
# Syntax:   deploy_packages.sh
#
# Usage:    Should only be used by Travis.
#
# Examples: scripts/travis/deploy_packages.sh

set -e

SCRIPTPATH="$( cd "$(dirname "$0")" ; pwd -P )"

if ! "${SCRIPTPATH}/../check_golang_version.sh"
then
    exit 1
fi
# Get the go build version.
GOLANG_VERSION=$("${SCRIPTPATH}/../get_golang_version.sh")

curl -sL -o ~/gimme https://raw.githubusercontent.com/travis-ci/gimme/master/gimme
chmod +x ~/gimme
eval "$(~/gimme "${GOLANG_VERSION}")"

scripts/travis/build.sh

export RELEASE_GENESIS_PROCESS=true
export NO_BUILD=true
export SkipCleanCheck=1
scripts/deploy_version.sh "${TRAVIS_BRANCH}" "$(./scripts/osarchtype.sh)"
