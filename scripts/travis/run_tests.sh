#!/usr/bin/env bash

set -e

SCRIPTPATH="$( cd "$(dirname "$0")" ; pwd -P )"
OS=$("${SCRIPTPATH}/../ostype.sh")

if [ "${BUILD_TYPE}" = "integration" ]; then
    ./test/scripts/run_integration_tests.sh
elif [ "${TRAVIS_EVENT_TYPE}" = "cron" ] || [[ "${TRAVIS_BRANCH}" =~ ^rel/ ]]; then
    if [[ "${OS}" != "darwin" ]]; then
	make fulltest -j4
    fi
else
    if [[ "${OS}" != "darwin" ]]; then
	make shorttest -j4
    fi
fi
