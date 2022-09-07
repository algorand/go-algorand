#!/bin/bash

scriptname="goal-app-info-test"
date "+${scriptname} start %Y%m%d_%H%M%S"

set -e
set -x
set -o pipefail
export SHELLOPTS

WALLET=$1

# Directory of this bash program
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

gcmd="goal -w ${WALLET}"

ACCOUNT=$(${gcmd} account list|awk '{ print $3 }')

EXTRA_PAGES=1
GLOBAL_BYTESLICES=2
GLOBAL_INTS=3
LOCAL_BYTESLICES=4
LOCAL_INTS=5

APPID=$(${gcmd} app create --creator ${ACCOUNT} --approval-prog ${DIR}/tealprogs/upgraded.teal --clear-prog ${DIR}/tealprogs/clear_program_state.teal --extra-pages ${EXTRA_PAGES} --global-byteslices ${GLOBAL_BYTESLICES} --global-ints ${GLOBAL_INTS} --local-byteslices ${LOCAL_BYTESLICES} --local-ints ${LOCAL_INTS} | grep Created | awk '{ print $6 }')

APP_INFO=$(${gcmd} app info --app-id $APPID)

ACTUAL_APPID=($(echo "$APP_INFO" | grep "Application ID:"))
ACTUAL_APP_ACCOUNT=($(echo "$APP_INFO" | grep "Application account:"))
ACTUAL_CREATOR=($(echo "$APP_INFO" | grep "Creator:"))
ACTUAL_APPROVAL_HASH=($(echo "$APP_INFO" | grep "Approval hash:"))
ACTUAL_CLEAR_HASH=($(echo "$APP_INFO" | grep "Clear hash:"))
ACTUAL_EXTRA_PAGES=($(echo "$APP_INFO" | grep "Extra program pages:"))
ACTUAL_GLOBAL_BYTESLICES=($(echo "$APP_INFO" | grep "Max global byteslices:"))
ACTUAL_GLOBAL_INTS=($(echo "$APP_INFO" | grep "Max global integers:"))
ACTUAL_LOCAL_BYTESLICES=($(echo "$APP_INFO" | grep "Max local byteslices:"))
ACTUAL_LOCAL_INTS=($(echo "$APP_INFO" | grep "Max local integers:"))

if [[ ${APPID} -ne ${ACTUAL_APPID[2]} ]]; then
    date "+${scriptname} FAIL returned app ID does not match ${APPID} != ${ACTUAL_APPID[2]} %Y%m%d_%H%M%S"
    false
fi

# Use the Python SDK to get the expected app escrow address
EXPECTED_APP_ACCOUNT=$(python3 -c "from algosdk.logic import get_application_address;print(get_application_address($APPID))")
if [[ $EXPECTED_APP_ACCOUNT != ${ACTUAL_APP_ACCOUNT[2]} ]]; then
    date "+${scriptname} FAIL returned app account does not match ${EXPECTED_APP_ACCOUNT} != ${ACTUAL_APP_ACCOUNT[2]} %Y%m%d_%H%M%S"
    false
fi

if [[ ${ACCOUNT} != ${ACTUAL_CREATOR[1]} ]]; then
    date "+${scriptname} FAIL returned app creator does not match ${ACCOUNT} != ${ACTUAL_CREATOR[1]} %Y%m%d_%H%M%S"
    false
fi

EXPECTED_APPROVAL_HASH="RBHEXJWG2M4T4OBDMNOQFKYYDPDMXQXZIMFZCINJAYVI5KPZLXVUWZRR2Q"
if [[ ${EXPECTED_APPROVAL_HASH} != ${ACTUAL_APPROVAL_HASH[2]} ]]; then
    date "+${scriptname} FAIL returned app approval hash does not match ${EXPECTED_APPROVAL_HASH} != ${ACTUAL_APPROVAL_HASH[2]} %Y%m%d_%H%M%S"
    false
fi

EXPECTED_CLEAR_HASH="YOE6C22GHCTKAN3HU4SE5PGIPN5UKXAJTXCQUPJ3KKF5HOAH646MKKCPDA"
if [[ ${EXPECTED_CLEAR_HASH} != ${ACTUAL_CLEAR_HASH[2]} ]]; then
    date "+${scriptname} FAIL returned app clear hash does not match ${EXPECTED_CLEAR_HASH} != ${ACTUAL_CLEAR_HASH[2]} %Y%m%d_%H%M%S"
    false
fi

if [[ ${EXTRA_PAGES} -ne ${ACTUAL_EXTRA_PAGES[3]} ]]; then
    date "+${scriptname} FAIL returned app extra pages does not match ${EXTRA_PAGES} != ${ACTUAL_EXTRA_PAGES[3]} %Y%m%d_%H%M%S"
    false
fi

if [[ ${GLOBAL_BYTESLICES} -ne ${ACTUAL_GLOBAL_BYTESLICES[3]} ]]; then
    date "+${scriptname} FAIL returned app global byte slice schema does not match ${GLOBAL_BYTESLICES} != ${ACTUAL_GLOBAL_BYTESLICES[3]} %Y%m%d_%H%M%S"
    false
fi

if [[ ${GLOBAL_INTS} -ne ${ACTUAL_GLOBAL_INTS[3]} ]]; then
    date "+${scriptname} FAIL returned app global int schema does not match ${GLOBAL_INTS} != ${ACTUAL_GLOBAL_INTS[3]} %Y%m%d_%H%M%S"
    false
fi

if [[ ${LOCAL_BYTESLICES} -ne ${ACTUAL_LOCAL_BYTESLICES[3]} ]]; then
    date "+${scriptname} FAIL returned app local byte slice schema does not match ${LOCAL_BYTESLICES} != ${ACTUAL_LOCAL_BYTESLICES[3]} %Y%m%d_%H%M%S"
    false
fi

if [[ ${LOCAL_INTS} -ne ${ACTUAL_LOCAL_INTS[3]} ]]; then
    date "+${scriptname} FAIL returned app local int schema does not match ${LOCAL_INTS} != ${ACTUAL_LOCAL_INTS[3]} %Y%m%d_%H%M%S"
    false
fi

date "+${scriptname} OK %Y%m%d_%H%M%S"
