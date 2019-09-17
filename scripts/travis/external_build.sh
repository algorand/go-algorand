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
# BUILD_PULL_REQUESTS_BUCKET
# AWS_ACCESS_KEY_ID (optional)
# AWS_SECRET_ACCESS_KEY (optional)
#

# exit on error
set -e

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

sudo apt-get install awscli

# create build request
echo "{ \"TRAVIS_BRANCH\" : \"${TRAVIS_BRANCH}\", \"TRAVIS_COMMIT\" : \"${TRAVIS_COMMIT}\", \"TRAVIS_PULL_REQUEST\" : \"${TRAVIS_PULL_REQUEST}\", \"AWS_ACCESS_KEY_ID\" : \"${AWS_ACCESS_KEY_ID}\", \"AWS_SECRET_ACCESS_KEY\" : \"${AWS_SECRET_ACCESS_KEY}\" }" > ${TRAVIS_BUILD_NUMBER}.json

if [ "${TRAVIS_PULL_REQUEST}" = "false" ]; then
    BUILD_REQUEST_PATH=s3://${BUILD_REQUESTS_BUCKET}/${TARGET_PLATFORM}/${TRAVIS_BUILD_NUMBER}.json
    BUILD_COMPLETE_PATH=s3://${BUILD_REQUESTS_BUCKET}/${TARGET_PLATFORM}/${TRAVIS_BUILD_NUMBER}-completed.json
    BUILD_LOG_PATH=s3://${BUILD_REQUESTS_BUCKET}/${TARGET_PLATFORM}/${TRAVIS_BUILD_NUMBER}-log
    NO_SIGN_REQUEST=
else
    BUILD_REQUEST_PATH=s3://${BUILD_PULL_REQUESTS_BUCKET}/${TARGET_PLATFORM}/${TRAVIS_BUILD_NUMBER}.json
    BUILD_COMPLETE_PATH=s3://${BUILD_PULL_REQUESTS_BUCKET}/${TARGET_PLATFORM}/${TRAVIS_BUILD_NUMBER}-completed.json
    BUILD_LOG_PATH=s3://${BUILD_PULL_REQUESTS_BUCKET}/${TARGET_PLATFORM}/${TRAVIS_BUILD_NUMBER}-log
    NO_SIGN_REQUEST=--no-sign-request
fi

set +e
# remove if it's already there, so the new build would replace it.
aws s3 rm ${BUILD_COMPLETE_PATH} ${NO_SIGN_REQUEST}

set -e
aws s3 cp ${TRAVIS_BUILD_NUMBER}.json ${BUILD_REQUEST_PATH} ${NO_SIGN_REQUEST}

# don't exit on error. we will test the error code.
set +e

echo "Waiting for build to start..."
end=$((SECONDS+60))
BUILD_STARTED=false
while [ $SECONDS -lt $end ]; do
    PENDING_BUILD=$(aws s3 ls ${BUILD_REQUEST_PATH} ${NO_SIGN_REQUEST} | wc -l | sed 's/[[:space:]]//g')
    if [ "${PENDING_BUILD}" != "1" ]; then
        BUILD_STARTED=true
        break
    fi
    sleep 1s
done

if [ "${BUILD_STARTED}" = "false" ]; then
    echo "Builder failed to kick off within elapsed time; aborting"
    exit 1
fi

echo "Waiting for build to complete..."
end=$((SECONDS+7200))
minute_end=$((SECONDS+60))
BUILD_COMPLETE=false
LOG_PRINT_COMPLETE=false
LOG_SEQ=1
while [ $SECONDS -lt $end ]; do
    GET_OUTPUT=$(aws s3 cp ${BUILD_COMPLETE_PATH} . ${NO_SIGN_REQUEST} 2> /dev/null)
    if [ "$?" = "0" ]; then
        echo "${GET_OUTPUT}"
        BUILD_COMPLETE=true
        break
    fi
    
    aws s3 ls ${BUILD_LOG_PATH}-${LOG_SEQ} ${NO_SIGN_REQUEST} 2> /dev/null
    if [ "$?" = "0" ]; then
        aws s3 cp ${BUILD_LOG_PATH}-${LOG_SEQ} - ${NO_SIGN_REQUEST} | cat
        if [ "$?" = "0" ]; then
            minute_end=$((SECONDS+60))
        fi
        ((LOG_SEQ++))
    fi

    if [ $SECONDS -gt $minute_end ]; then
        minute_end=$((SECONDS+60))
        echo "Still waiting for build to complete..."
    fi
    sleep 1s
done

aws s3 ls ${BUILD_LOG_PATH}-${LOG_SEQ} . ${NO_SIGN_REQUEST} 2> /dev/null
if [ "$?" = "0" ]; then
    aws s3 cp ${BUILD_LOG_PATH}-${LOG_SEQ} - ${NO_SIGN_REQUEST} | cat
fi

if [ "${BUILD_COMPLETE}" = "false" ]; then
    echo "Builder failed to finish building within elapsed time; aborting"
    exit 1
fi

BUILD_ERROR=$(cat ./${TRAVIS_BUILD_NUMBER}-completed.json | jq '.error')
cat ./${TRAVIS_BUILD_NUMBER}-completed.json | jq -r '.log'

if [ "${BUILD_ERROR}" != "0" ]; then
    exit 1
fi
