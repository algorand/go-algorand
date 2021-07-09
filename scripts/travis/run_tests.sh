#!/usr/bin/env bash

set -e

if [ "${BUILD_TYPE}" = "integration" ]; then
    # Run short tests when doing pull requests; leave the long testing for nightly runs.
    if [[ "${TRAVIS_BRANCH}" =~ ^rel/nightly ]]; then
        SHORTTEST=
    else
        SHORTTEST=-short
    fi
    export SHORTTEST 
    "${SCRIPTPATH}/travis_retry.sh" make integration
elif [ "${TRAVIS_EVENT_TYPE}" = "cron" ] || [[ "${TRAVIS_BRANCH}" =~ ^rel/ ]]; then
    make fulltest -j2
else
    make shorttest -j2
fi
