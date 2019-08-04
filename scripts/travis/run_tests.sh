#!/usr/bin/env bash

set -e

if [ "${BUILD_TYPE}" = "integration" ]; then
    ./test/scripts/run_integration_tests.sh
elif [ "${TRAVIS_EVENT_TYPE}" = "cron" ] || [[ "${TRAVIS_BRANCH}" =~ ^rel/ ]]; then
    make fulltest -j4
else
    make shorttest -j4
fi
