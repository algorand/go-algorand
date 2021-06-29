#!/usr/bin/env bash

set -e

SCRIPTPATH="$( cd "$(dirname "$0")" ; pwd -P )"

if $CIRCLECI; then
  export GOPATH=/home/circleci/.go_workspace;
else
  export GOPATH=$(go env GOPATH)
fi

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
    "${SCRIPTPATH}/travis_retry.sh" make fulltest -j2
else
    "${SCRIPTPATH}/travis_retry.sh" make shorttest -j2
fi
