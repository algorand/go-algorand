#!/usr/bin/env bash

# external_build.sh - Enqueue the build request for the specified platform
#
# Syntax:   external_build.sh
#
# Usage:    Should only be used by Travis
#
# Examples: scripts/travis/external_build.sh
#
# Use the following travis varaibles:
# BUILD_TYPE
# TARGET_PLATFORM
# TRAVIS_BRANCH
# TRAVIS_COMMIT
# TRAVIS_BUILD_NUMBER
# BUILD_REQUESTS_BUCKET
# BUILD_PULL_EQUESTS_BUCKET
#

# exit on error
set -e

if [ "${BUILD_TYPE}" != "external_build" ]; then
    echo "error: wrong build type specified '${BUILD_TYPE}'"
    exit 1
fi

if [ "${TARGET_PLATFORM}" != "linux-arm64" ]; then
    echo "error: unsupported platform '${TARGET_PLATFORM}'"
    exit 1
fi

if [ "${TRAVIS_PULL_REQUEST}" = "false" ]; then
    if [ "${BUILD_REQUESTS_BUCKET}" = "" ]; then
        echo "error: BUILD_REQUESTS_BUCKET was not specified."
        exit 1
    fi
else
    if [ "${BUILD_PULL_REQUESTS_BUCKET}" = "" ]; then
        echo "error: BUILD_PULL_REQUESTS_BUCKET was not specified."
        exit 1
    fi
fi

sudo apt-get install awscli
# create build request
echo "{ \"TRAVIS_BRANCH\" = \"${TRAVIS_BRANCH}\", \"TRAVIS_COMMIT\"=\"${TRAVIS_COMMIT}\" }" > ${TRAVIS_BUILD_NUMBER}.json

if [ "${TRAVIS_PULL_REQUEST}" = "false" ]; then
    BUILD_REQUEST_PATH=s3://${BUILD_REQUESTS_BUCKET}/${TARGET_PLATFORM}/${TRAVIS_BUILD_NUMBER}.json
    NO_SIGN_REQUEST=
else
    BUILD_REQUEST_PATH=s3://${BUILD_PULL_REQUESTS_BUCKET}/${TARGET_PLATFORM}/${TRAVIS_BUILD_NUMBER}.json
    NO_SIGN_REQUEST=--no-sign-request
fi

aws s3 cp ${TRAVIS_BUILD_NUMBER}.json ${BUILD_REQUEST_PATH} ${NO_SIGN_REQUEST}

# don't exit on error. we will test the error code.
set +e

echo "Waiting for build to start..."
end=$((SECONDS+30))
BUILD_STARTED=false
while [ $SECONDS -lt $end ]; do
    PENDING_BUILD=$(aws s3 ls ${BUILD_REQUEST_PATH} ${NO_SIGN_REQUEST} | wc -l | sed 's/[[:space:]]//g')
    if [ "${PENDING_BUILD}" != "1" ]; do
        BUILD_STARTED=true
        break
    fi
done

if [ "${BUILD_STARTED}" = "false" ]; do
    echo "Builder failed to kick off within elapsed time; aborting"
    exit 1
fi

echo "TODO : Wait until builder is done and print out builder output"

