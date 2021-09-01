#!/usr/bin/env bash

set -e

if [ "${BUILD_TYPE}" = "integration" ]; then
    # Travis has trouble with the expect tests.
    if [ "${TRAVIS}" = "true" ]; then
      export RUN_EXPECT="FALSE"
    fi

    # Run short tests when doing pull requests; leave the long testing for nightly runs.
    if [[ "${TRAVIS_BRANCH}" =~ ^rel/nightly ]] || [[ "${TRAVIS_BRANCH}" =~ ^hotfix/ ]]; then
        SHORTTEST=
    else
        SHORTTEST=-short
    fi
    export SHORTTEST 
    make integration
elif [ "${TRAVIS_EVENT_TYPE}" = "cron" ] || [[ "${TRAVIS_BRANCH}" =~ ^rel/ ]] || [[ "${TRAVIS_BRANCH}" =~ ^hotfix/ ]]; then
    make fulltest -j2
else
    make shorttest -j2
fi
