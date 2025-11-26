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
OSARCH=$("${SCRIPTPATH}/../osarchtype.sh")
# Get the go build version.
GOLANG_VERSION=$("${SCRIPTPATH}/../get_golang_version.sh")

curl -sL -o ~/gimme https://raw.githubusercontent.com/travis-ci/gimme/master/gimme
chmod +x ~/gimme
eval "$(~/gimme "${GOLANG_VERSION}")"

if ! "${SCRIPTPATH}/../check_golang_version.sh"
then
    exit 1
fi

if [ "${NIGHTLY_BUILD}" == "true" ]; then
    # we want to rebuild universal binaries for nightly builds
    if [ "${OSARCH}" == "darwin/arm64" ]; then
        ./scripts/travis/build.sh --make_universal
        OSARCH="darwin/universal"
    else
        scripts/travis/build.sh --make_debug
    fi
    NO_BUILD=true
fi

if [ -z "${NO_BUILD}" ] || [ "${NO_BUILD}" != "true" ]; then
    scripts/travis/build.sh
fi

export RELEASE_GENESIS_PROCESS=true
export NO_BUILD=true
export SkipCleanCheck=1
scripts/deploy_version.sh "${TRAVIS_BRANCH}" "${OSARCH}"
