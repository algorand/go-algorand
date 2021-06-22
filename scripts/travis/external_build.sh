#!/usr/bin/env bash

# external_build.sh - Enqueue the build request for the specified platform
#
# Syntax:   external_build.sh
#
# Usage:    Should only be used by Travis
#
# Examples: scripts/travis/external_build.sh
#
# Use the following travis variables:
# BUILD_TYPE
# TARGET_PLATFORM
# TRAVIS_BRANCH
# TRAVIS_COMMIT
# TRAVIS_JOB_NUMBER
# BUILD_REQUESTS_BUCKET
# BUILD_PULL_REQUESTS_BUCKET
# AWS_ACCESS_KEY_ID (optional)
# AWS_SECRET_ACCESS_KEY (optional)
#

# exit on error
set -e

BUILD_TARGET=$1

if [ "${BUILD_TYPE}" != "external_build" ]; then
    echo "error: wrong build type specified '${BUILD_TYPE}'"
    exit 1
fi

if [ "${TARGET_PLATFORM}" != "linux-arm64" ] && [ "${TARGET_PLATFORM}" != "linux-arm" ]; then
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

if [ "${BUILD_TARGET}" = "" ]; then
    echo "error: missing build target argument"
    exit 1
fi

BUILDID=${TRAVIS_JOB_NUMBER/./000}

# create build request
echo "{ \"S3_RELEASE_BUCKET\" : \"${S3_RELEASE_BUCKET}\", \"TRAVIS_BRANCH\" : \"${TRAVIS_BRANCH}\", \"TRAVIS_COMMIT\" : \"${TRAVIS_COMMIT}\", \"TRAVIS_PULL_REQUEST\" : \"${TRAVIS_PULL_REQUEST}\", \"AWS_ACCESS_KEY_ID\" : \"${AWS_ACCESS_KEY_ID}\", \"AWS_SECRET_ACCESS_KEY\" : \"${AWS_SECRET_ACCESS_KEY}\", \"EXEC\":\"${BUILD_TARGET}\" }" > "${BUILDID}.json"

if [ "${TRAVIS_PULL_REQUEST}" = "false" ]; then
    BUILD_REQUEST_PATH=s3://${BUILD_REQUESTS_BUCKET}/${TARGET_PLATFORM}/${BUILDID}.json
    BUILD_COMPLETE_PATH=s3://${BUILD_REQUESTS_BUCKET}/${TARGET_PLATFORM}/${BUILDID}-completed.json
    BUILD_LOG_PATH=s3://${BUILD_REQUESTS_BUCKET}/${TARGET_PLATFORM}/${BUILDID}-log
    NO_SIGN_REQUEST=
    echo "Build request : { \"S3_RELEASE_BUCKET\" : \"${S3_RELEASE_BUCKET}\", \"TRAVIS_BRANCH\" : \"${TRAVIS_BRANCH}\", \"TRAVIS_COMMIT\" : \"${TRAVIS_COMMIT}\", \"TRAVIS_PULL_REQUEST\" : \"${TRAVIS_PULL_REQUEST}\", \"AWS_ACCESS_KEY_ID\" : \"*****\", \"AWS_SECRET_ACCESS_KEY\" : \"*****\", \"EXEC\":\"${BUILD_TARGET}\" }"    
else
    BUILD_REQUEST_PATH=s3://${BUILD_PULL_REQUESTS_BUCKET}/${TARGET_PLATFORM}/${BUILDID}.json
    BUILD_COMPLETE_PATH=s3://${BUILD_PULL_REQUESTS_BUCKET}/${TARGET_PLATFORM}/${BUILDID}-completed.json
    BUILD_LOG_PATH=s3://${BUILD_PULL_REQUESTS_BUCKET}/${TARGET_PLATFORM}/${BUILDID}-log
    NO_SIGN_REQUEST=--no-sign-request
    echo "Build request : $(cat "${BUILDID}.json")"
fi

set +e
# remove if it's already there, so the new build would replace it.
aws s3 rm "${BUILD_COMPLETE_PATH}" ${NO_SIGN_REQUEST}
# delete the first log for this build task. The build host would
# delete any n+1 log file before creating the n-th log file.
aws s3 rm "${BUILD_LOG_PATH}"-1 ${NO_SIGN_REQUEST}

set -e
aws s3 cp "${BUILDID}.json" "${BUILD_REQUEST_PATH}" ${NO_SIGN_REQUEST}

# don't exit on error. we will test the error code.
set +e

echo "Waiting for build to start..."
endWait=$((SECONDS+600))
msgTimer=$((SECONDS+60))
BUILD_STARTED=false
while [ $SECONDS -lt $endWait ]; do
    PENDING_BUILD=$(aws s3 ls "${BUILD_REQUEST_PATH}" ${NO_SIGN_REQUEST} | wc -l | sed 's/[[:space:]]//g')
    if [ "${PENDING_BUILD}" != "1" ]; then
        BUILD_STARTED=true
        break
    fi
    if [ $SECONDS -gt $msgTimer ]; then
        msgTimer=$((SECONDS+60))
        echo "Still waiting for build to start..."
    fi
    sleep 1s
done

if [ "${BUILD_STARTED}" = "false" ]; then
    echo "Builder failed to kick off within elapsed time; aborting"
    exit 1
fi

echo "Waiting for build to complete..."
./scripts/travis/external_build_printlog.sh "${BUILD_LOG_PATH}" "${BUILD_COMPLETE_PATH}" ${NO_SIGN_REQUEST}
exit $?
