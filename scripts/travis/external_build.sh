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
#

if [ "${BUILD_TYPE}" != "external_build" ]; then
    exit 1
fi

if [ "${TARGET_PLATFORM}" != "linux-arm64" ]; then
    exit 1
fi

sudo apt-get install awscli
# create build request
echo "{ \"TRAVIS_BRANCH\" = \"${TRAVIS_BRANCH}\", \"TRAVIS_COMMIT\"=\"${TRAVIS_COMMIT}\" }" > ${TRAVIS_BUILD_NUMBER}.json
aws s3 mb s3://${BUILD_REQUESTS_BUCKET}/${TARGET_PLATFORM}
aws s3 cp ${TRAVIS_BUILD_NUMBER}.json s3://${BUILD_REQUESTS_BUCKET}/${TARGET_PLATFORM}/${TRAVIS_BUILD_NUMBER}.json



