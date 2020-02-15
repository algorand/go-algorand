#!/usr/bin/env bash

# deploy_packages.sh - Script executed by Travis for 'Deploy' step, if build / tests succeed
#
# Syntax:   deploy_packages.sh
#
# Usage:    Should only be used by Travis.
#
# Examples: scripts/travis/deploy_packages.sh

set -e
scripts/travis/build.sh

export RELEASE_GENESIS_PROCESS=true
export NO_BUILD=true
export SkipCleanCheck=1
scripts/deploy_version.sh ${TRAVIS_BRANCH} $(./scripts/osarchtype.sh)
