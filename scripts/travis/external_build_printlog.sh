#!/usr/bin/env bash

# external_build.sh - Enqueue the build request for the specified platform
#
# Syntax:   external_build.sh
#
# Usage:    Should only be used by Travis
#
# Examples: scripts/travis/external_build.sh <BUILD_LOG_PATH> <BUILD_COMPLETE_PATH> <NO_SIGN_REQUEST>
#

BUILD_LOG_PATH=$1
BUILD_COMPLETE_PATH=$2
NO_SIGN_REQUEST=$3

# don't exit on error. we will test the error code.
set +e

end=$((SECONDS+7200))
minute_end=$((SECONDS+60))
BUILD_COMPLETE=false
LOG_SEQ=1
while [ $SECONDS -lt $end ]; do
    aws s3 ls "${BUILD_LOG_PATH}"-"${LOG_SEQ}" "${NO_SIGN_REQUEST}" 2> /dev/null > /dev/null
    if [ "$?" = "0" ]; then
        while true ; do
            aws s3 cp "${BUILD_LOG_PATH}"-"${LOG_SEQ}" - "${NO_SIGN_REQUEST}" | cat
            if [ "$?" = "0" ]; then
                ((LOG_SEQ++))
            else
                break
            fi
        done
        minute_end=$((SECONDS+60))
    else
        GET_OUTPUT=$(aws s3 cp "${BUILD_COMPLETE_PATH}" ./build-completed.json "${NO_SIGN_REQUEST}" 2> /dev/null)
        if [ "$?" = "0" ]; then
            echo "${GET_OUTPUT}"
            BUILD_COMPLETE=true
            break
        fi
    fi

    if [ $SECONDS -gt $minute_end ]; then
        minute_end=$((SECONDS+60))
        echo "Still waiting for build to complete..."
    fi
    sleep 1s
done

aws s3 ls "${BUILD_LOG_PATH}"-"${LOG_SEQ}" . "${NO_SIGN_REQUEST}" 2> /dev/null > /dev/null
if [ "$?" = "0" ]; then
    aws s3 cp "${BUILD_LOG_PATH}"-"${LOG_SEQ}" - "${NO_SIGN_REQUEST}" | cat
fi

if [ "${BUILD_COMPLETE}" = "false" ]; then
    echo "Builder failed to finish building within elapsed time; aborting"
    exit 1
fi

BUILD_ERROR=$(jq '.error' < ./build-completed.json)
jq -r '.log' < ./build-completed.json

if [ "${BUILD_ERROR}" != "0" ]; then
    exit 1
fi

exit 0
