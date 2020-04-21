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
LOG_WAITING_START=$SECONDS
BUILD_COMPLETE=false
LOG_SEQ=1
while [ $SECONDS -lt $end ]; do
    aws s3 ls "${BUILD_LOG_PATH}"-"${LOG_SEQ}" ${NO_SIGN_REQUEST} 2> /dev/null > /dev/null
    if [ "$?" = "0" ]; then
        while true ; do
            if [ "${NO_SIGN_REQUEST}" == "--no-sign-request" ]; then
                URL="${BUILD_LOG_PATH}-${LOG_SEQ}"
                URL="${URL#s3://}"
                URL="${URL/\//.s3.amazonaws.com/}"
                URL="https://${URL}"
                LOG_CHUNK=$(curl  --fail "${URL}" 2> /dev/null)
            else
                LOG_CHUNK=$(aws s3 cp "${BUILD_LOG_PATH}"-"${LOG_SEQ}" - ${NO_SIGN_REQUEST} 2> /dev/null)
            fi
            if [ "$?" = "0" ]; then
                echo "${LOG_CHUNK}"
                ((LOG_SEQ++))
            else
                break
            fi
        done
        minute_end=$((SECONDS+60))
    else
        GET_OUTPUT=$(aws s3 cp "${BUILD_COMPLETE_PATH}" ./build-completed.json ${NO_SIGN_REQUEST} 2> /dev/null)
        if [ "$?" = "0" ]; then
            echo "${GET_OUTPUT}"
            BUILD_COMPLETE=true
            break
        fi
    fi

    if [ $SECONDS -gt $minute_end ]; then
        minute_end=$((SECONDS+60))
        echo "Still waiting for build to complete $(((SECONDS-LOG_WAITING_START)/60))m:$(((SECONDS-LOG_WAITING_START)%60))s..."
    fi

    if [ "${TRAVIS}" = "true" ]; then
        # under travis, if we have passed the 1h:45m mark, the build is going to likely fail due to timeout.
        # instead of failing, we want to exit the build with success, indicating where the log could be retrieved later on.
        # ( note that there migth be an issue with that build, but we don't want to cap it via travis timeouts. )
        if [ $((SECONDS-LOG_WAITING_START)) -gt $((60*105)) ]; then
            echo "Build is taking too long. Travis is going to timeout this build, so we'll tell travis that we're done for now."
            echo "Once this build is complete, you could get a complete log by typing:"
            echo "./scripts/travis/external_build_printlog.sh \"${BUILD_LOG_PATH}\" \"${BUILD_COMPLETE_PATH}\" ${NO_SIGN_REQUEST}"
            exit 0
        fi
    fi
    sleep 1s
done

aws s3 ls "${BUILD_LOG_PATH}"-"${LOG_SEQ}" . ${NO_SIGN_REQUEST} 2> /dev/null > /dev/null
if [ "$?" = "0" ]; then
    LOG_CHUNK=$(aws s3 cp "${BUILD_LOG_PATH}"-"${LOG_SEQ}" - ${NO_SIGN_REQUEST} 2> /dev/null)
    if [ "$?" = "0" ]; then
        echo "${LOG_CHUNK}"
    fi
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
