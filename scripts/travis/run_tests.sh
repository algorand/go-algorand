#!/usr/bin/env bash

set -e

export GOPATH=$(go env GOPATH)
cd ${GOPATH}/src/github.com/algorand/go-algorand

if [ "${BUILD_TYPE}" = "integration" ]; then
    ./test/scripts/run_integration_tests.sh
elif [ "${TRAVIS_EVENT_TYPE}" = "cron" ] || [[ "${TRAVIS_BRANCH}" =~ ^rel/ ]]; then
    make fulltest -j4
else
    make shorttest -j4
fi
