#!/usr/bin/env bash

set -e

SCRIPTPATH="$( cd "$(dirname "$0")" ; pwd -P )"
OS=$("${SCRIPTPATH}/../ostype.sh")
ARCH=$("${SCRIPTPATH}/../archtype.sh")

if [ "${BUILD_TYPE}" = "integration" ]; then
    # Run short tests when doing pull requests; leave the long testing for nightly runs.
    if [[ "${TRAVIS_BRANCH}" =~ ^rel/nightly ]]; then
        SHORTTEST=
    else
        SHORTTEST=-short
    fi
    export SHORTTEST 
    ./test/scripts/run_integration_tests.sh
elif [ "${TRAVIS_EVENT_TYPE}" = "cron" ] || [[ "${TRAVIS_BRANCH}" =~ ^rel/ ]]; then
    if [ "${OS}" != "darwin" ] && [ "${ARCH}" != "arm64" ]; then
	make fulltest -j4
    fi
else
    if [[ "${OS}" != "darwin" ]]; then
	make shorttest -j4
    fi
fi
