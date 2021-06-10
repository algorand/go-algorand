#!/usr/bin/env bash

set -e

SCRIPTPATH="$( cd "$(dirname "$0")" ; pwd -P )"
OS=$("${SCRIPTPATH}/../ostype.sh")

if [ "${BUILD_TYPE}" = "integration" ]; then
    # Run short tests when doing pull requests; leave the long testing for nightly runs.
    if [[ "${TRAVIS_BRANCH}" =~ ^rel/nightly ]]; then
        SHORTTEST=
    else
        SHORTTEST=-short
    fi
    export SHORTTEST 
    make integration
else
    if [[ "${OS}" != "darwin" ]]; then
        # setting it to 1 disable parallel making. This is done specicifically for travis, as travis seems to
        # have memory limitations and setting this to 1 could reduce the likelihood of hitting these.
	    make fulltest
    fi
fi
