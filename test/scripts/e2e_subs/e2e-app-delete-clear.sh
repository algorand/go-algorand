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

GLOBAL_INTS=2

# Succeed in creating app with on-completion delete
APPID=$(${gcmd} app create --creator ${ACCOUNT}  --on-completion "DeleteApplication" --approval-prog "${PROGRAM_FILE}" --clear-prog "${PROGRAM_FILE}" --global-ints ${GLOBAL_INTS} | grep Created | awk '{ print $6 }')
# Check that the app is not created
APPID_CHECK=$(${gcmd} app info --app-id $APPID 2>&1 || true)
EXPERROR="application does not exist"
if [[ $APPID_CHECK != *"${EXPERROR}"* ]]; then
    date '+${scriptname} FAIL the deleted application should not exist %Y%m%d_%H%M%S'
    false
fi

# Fail if creating app with on-completion clear
RES=$(${gcmd} app create --creator ${ACCOUNT}  --on-completion "ClearState" --approval-prog "${PROGRAM_FILE}" --clear-prog "${PROGRAM_FILE}" --global-ints ${GLOBAL_INTS} 2>&1 || true  ) 
EXPERROR1='cannot clear state'
EXPERROR2='is not currently opted in'
if [[ $RES != *"${EXPERROR1}"*"${EXPERROR2}"* ]]; then
    date '+${scriptname} FAIL should fail to create app with on-completion ClearState %Y%m%d_%H%M%S'
    false
fi
