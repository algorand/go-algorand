#!/usr/bin/env bash

# run.sh - Invokes the build host
#
# Syntax:   run.sh
#
# Usage:    Should only be used by a build host server.
#
# Examples: scripts/buildhost/run.sh
#
# Use the following travis varaibles:
# BUILD_REQUESTS_BUCKET
# BUILD_PULL_EQUESTS_BUCKET
# AWS_ACCESS_KEY_ID
# AWS_SECRET_ACCESS_KEY
#

# no exit on error
set +e

if [ "${AWS_ACCESS_KEY_ID}" = "" ]; then
    echo "error: AWS_ACCESS_KEY_ID was not specified."
    exit 1
fi

if [ "${AWS_SECRET_ACCESS_KEY}" = "" ]; then
    echo "error: AWS_SECRET_ACCESS_KEY was not specified."
    exit 1
fi

if [ "${BUILD_REQUESTS_BUCKET}" = "" ]; then
    echo "error: BUILD_REQUESTS_BUCKET was not specified."
    exit 1
fi

if [ "${BUILD_PULL_REQUESTS_BUCKET}" = "" ]; then
    echo "error: BUILD_PULL_REQUESTS_BUCKET was not specified."
    exit 1
fi

NO_SIGN_REQUEST=--no-sign-request

checkBucket () {
    local BUCKET=$1
    local NO_SIGN=$2

    aws s3 ls --recursive s3://${BUCKET} ${NO_SIGN} | awk '{print $4}' | grep -ve "-completed\.json" | grep -ve "/$" > buildRequests
    if [ "$?" != "0" ]; then
        rm buildRequests
        return 1
    fi

    REQUESTS_COUNT=$(cat buildRequests | wc -l | sed 's/[[:space:]]//g')
    if [ "$?" != "0" ]; then
        rm buildRequests
        return 1
    fi

    if [ "${REQUESTS_COUNT}" = "0" ]; then
        # nothing to do.
        rm buildRequests
        return 0
    fi

    FIRST_FILE=$(head -1 buildRequests)
    rm buildRequests
    mkdir -p tmp
    aws s3 cp s3://${BUCKET}/${FIRST_FILE} ./tmp/${FIRST_FILE} ${NO_SIGN}
    if [ "$?" != "0" ]; then
        # we failed to download, exit.
        rm -rf tmp
        return 0
    fi

    aws s3 rm s3://${BUCKET}/${FIRST_FILE} ${NO_SIGN}
    if [ "$?" != "0" ]; then
        # we failed to delete ( i.e. own build task ), exit.
        rm -rf tmp
        return 0
    fi

    ARCH=$(echo "${FIRST_FILE}" | cut -d "/" -f 1)
    ARCH_BUILDER="./${ARCH}.sh"
    if [ ! -f "${ARCH_BUILDER}" ]; then
        # invalid architecture
        echo "builder for architecture ${ARCH} could not be found"
        rm -rf tmp
        return 1
    fi

    TEMPDIR=$(mktemp -d 2>/dev/null || mktemp -d -t "tmp")
    FILENAME=$(echo "${FIRST_FILE}" | cut -d "/" -f 2)
    cp ./tmp/${FIRST_FILE} ${TEMPDIR}/${FILENAME}
    rm -rf tmp

    OUTPUTFILE=${FIRST_FILE/.json/-completed.json}

    ${ARCH_BUILDER} ${TEMPDIR}/${FILENAME} ${OUTPUTFILE} ${BUCKET} ${NO_SIGN} &
    return 0
}

while true; do
    checkBucket ${BUILD_REQUESTS_BUCKET}
    checkBucket ${BUILD_PULL_REQUESTS_BUCKET} ${NO_SIGN_REQUEST}
    sleep 0.5s
done

