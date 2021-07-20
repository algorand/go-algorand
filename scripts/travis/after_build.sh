#!/usr/bin/env bash

# after_build.sh - Performs our profiling and coverage tasks on Travis after tests
#
# Syntax:   after_build.sh
#
# Usage:    Should only be used by Travis
#
# Examples: scripts/travis/after_build.sh

if [ "${TRAVIS_EVENT_TYPE}" = "cron" ] || [[ "${TRAVIS_BRANCH}" =~ ^rel/ ]]; then
    if [ "${BUILD_TYPE}" != "integration" ]; then
        cd "$(dirname "$0")"/../.. || exit 1
        make prof
        rm ./node/node.test
    fi;
fi;
