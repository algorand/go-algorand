#!/bin/bash

filename=$(basename "$0")
scriptname="${filename%.*}"
date "+${scriptname} start %Y%m%d_%H%M%S"

set -e
set -x
set -o pipefail
export SHELLOPTS

WALLET=$1

gcmd="goal -w ${WALLET}"

ACCOUNT=$(${gcmd} account list|awk '{ print $3 }')

# approval program
printf '#pragma version 2\nint 1' > "${TEMPDIR}/simple.teal"
PROGRAM_FILE="${TEMPDIR}/simple.teal"

# Create app with two global ints
APPID=$(${gcmd} app create --creator ${ACCOUNT} --approval-prog "${PROGRAM_FILE}" --clear-prog "${PROGRAM_FILE}" --global-ints 2 | grep Created | awk '{ print $6 }')

APP_INFO=$(${gcmd} app info --app-id $APPID 2>&1)
EXPECT="Max global integers:   2"
if [[ $APP_INFO != *"${EXPECT}"* ]]; then
    date "+${scriptname} FAIL wrong initial schema %Y%m%d_%H%M%S"
    false
fi

${gcmd} app update --app-id $APPID --from ${ACCOUNT} --approval-prog "${PROGRAM_FILE}" --clear-prog "${PROGRAM_FILE}" --global-ints 3

APP_INFO=$(${gcmd} app info --app-id $APPID 2>&1)
EXPECT="Max global integers:   3"
if [[ $APP_INFO != *"${EXPECT}"* ]]; then
    date "+${scriptname} FAIL wrong updated schema %Y%m%d_%H%M%S"
    false
fi

${gcmd} app update --app-id $APPID --from ${ACCOUNT} --approval-prog "${PROGRAM_FILE}" --clear-prog "${PROGRAM_FILE}" --global-ints 1 --extra-pages 2

APP_INFO=$(${gcmd} app info --app-id $APPID 2>&1)
EXPECT="Max global integers:   1"
if [[ $APP_INFO != *"${EXPECT}"* ]]; then
    date "+${scriptname} FAIL wrong shrunken schema %Y%m%d_%H%M%S"
    false
fi
EXPECT="Extra program pages:   2"
if [[ $APP_INFO != *"${EXPECT}"* ]]; then
    date "+${scriptname} FAIL wrong program pages schema %Y%m%d_%H%M%S"
    false
fi
