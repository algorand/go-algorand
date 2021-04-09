#!/bin/bash

date '+app-simple-test start %Y%m%d_%H%M%S'

set -e
set -x
set -o pipefail
export SHELLOPTS

WALLET=$1

gcmd="goal -w ${WALLET}"

ACCOUNT=$(${gcmd} account list|awk '{ print $3 }')
GLOBAL_INTS=2

# Version 2 approval program
printf '#pragma version 2\nint 1' > "${TEMPDIR}/simple.teal"
PROGRAM=($(${gcmd} clerk compile "${TEMPDIR}/simple.teal"))

# Version 1 approval program
printf 'int 1' > "${TEMPDIR}/simplev1.teal"

# Fail in creating app with v1 approval program
RES=$(${gcmd} app create --creator ${ACCOUNT} --approval-prog "${TEMPDIR}/simplev1.teal" --clear-prog "${TEMPDIR}/simple.teal" --global-byteslices 0 --global-ints ${GLOBAL_INTS} --local-byteslices 0 --local-ints 0 2>&1 || true)
EXPERROR='program version must be >= 2 for this transaction group'
if [[ $RES != *"${EXPERROR}"* ]]; then
    date '+app-create-test FAIL should fail to create app with v1 approval program %Y%m%d_%H%M%S'
    false
fi

# Fail in creating app with v1 clearstate program
RES=$(${gcmd} app create --creator ${ACCOUNT} --approval-prog "${TEMPDIR}/simple.teal" --clear-prog "${TEMPDIR}/simplev1.teal" --global-byteslices 0 --global-ints ${GLOBAL_INTS} --local-byteslices 0 --local-ints 0 2>&1 || true)
EXPERROR='program version must be >= 2 for this transaction group'
if [[ $RES != *"${EXPERROR}"* ]]; then
    date '+app-create-test FAIL should fail to create app with v1 clearstate program %Y%m%d_%H%M%S'
    false
fi

# Succeed in creating app that approves all transactions
APPID=$(${gcmd} app create --creator ${ACCOUNT} --approval-prog "${TEMPDIR}/simple.teal" --clear-prog "${TEMPDIR}/simple.teal" --global-byteslices 0 --global-ints ${GLOBAL_INTS} --local-byteslices 0 --local-ints 0 | grep Created | awk '{ print $6 }')

# Check that parameters were set correctly
APPID_CHECK=($(${gcmd} app info --app-id $APPID | grep "ID"))
CREATOR_CHECK=($(${gcmd} app info --app-id $APPID | grep "Creator"))
GLOBAL_CHECK=($(${gcmd} app info --app-id $APPID | grep "global integers"))
PROGRAM_CHECK=($(${gcmd} app info --app-id $APPID | grep "Approval"))

if [[ ${APPID} != ${APPID_CHECK[2]} ]]; then
    date '+app-create-test FAIL returned app ID does not match ${APPID} != ${APPID_CHECK[2]} %Y%m%d_%H%M%S'
    false
fi

if [[ ${ACCOUNT} != ${CREATOR_CHECK[1]} ]]; then
    date '+app-create-test FAIL returned creator does not match ${ACCOUNT} != ${CREATOR_CHECK[1]} %Y%m%d_%H%M%S'
    false
fi

if [[ ${GLOBAL_INTS} != ${GLOBAL_CHECK[3]} ]]; then
    date '+app-create-test FAIL returned global integers does not match ${GLOBAL_CHECK[3]} != ${GLOBAL_INTS} %Y%m%d_%H%M%S'
    false
fi

if [[ ${PROGRAM[1]} != ${PROGRAM_CHECK[2]} ]]; then
    date '+app-create-test FAIL returned app ID does not match ${PROGRAM[1]} != ${PROGRAM_CHECK[2]} %Y%m%d_%H%M%S'
    false
fi

# Fail to create app if approval program rejects creation
RES=$(${gcmd} app create --creator ${ACCOUNT} --approval-prog <(printf '#pragma version 2\nint 0') --clear-prog "${TEMPDIR}/simple.teal" --global-byteslices 0 --global-ints 0 --local-byteslices 0 --local-ints 0 2>&1 || true)
EXPERROR='rejected by ApprovalProgram'
if [[ $RES != *"${EXPERROR}"* ]]; then
    date '+app-create-test FAIL txn with failing approval prog should be rejected %Y%m%d_%H%M%S'
    false
fi

# Succeed in opting into the first app
${gcmd} app optin --app-id $APPID --from $ACCOUNT

# Succeed in closing out of the first app
${gcmd} app closeout --app-id $APPID --from $ACCOUNT

# Fail to close out twice
RES=$(${gcmd} app closeout --app-id $APPID --from $ACCOUNT 2>&1 || true)
EXPERROR='is not opted in'
if [[ $RES != *"${EXPERROR}"* ]]; then
    date '+app-create-test FAIL closing out twice should fail %Y%m%d_%H%M%S'
    false
fi

# Succeed in opting into the first app again
${gcmd} app optin --app-id $APPID --from $ACCOUNT

# Succeed in clearing state for the app
${gcmd} app clear --app-id $APPID --from $ACCOUNT

# Fail to clear twice
RES=$(${gcmd} app clear --app-id $APPID --from $ACCOUNT 2>&1 || true)
EXPERROR='not currently opted in'
if [[ $RES != *"${EXPERROR}"* ]]; then
    date '+app-create-test FAIL clearing state twice should fail %Y%m%d_%H%M%S'
    false
fi

# Create an application with clear program always errs
# Ensure clear still works
APPID=$(${gcmd} app create --creator ${ACCOUNT} --approval-prog <(printf '#pragma version 2\nint 1') --clear-prog <(printf '#pragma version 2\nerr') --global-byteslices 0 --global-ints 0 --local-byteslices 0 --local-ints 0 | grep Created | awk '{ print $6 }')

# Should succeed to opt in
${gcmd} app optin --app-id $APPID --from $ACCOUNT

# Succeed in clearing state for the app
${gcmd} app clear --app-id $APPID --from $ACCOUNT

# Create an application with clear program always fails
# Ensure clear still works
APPID=$(${gcmd} app create --creator ${ACCOUNT} --approval-prog <(printf '#pragma version 2\nint 1') --clear-prog <(printf '#pragma version 2\nint 0') --global-byteslices 0 --global-ints 0 --local-byteslices 0 --local-ints 0 | grep Created | awk '{ print $6 }')

# Should succeed to opt in
${gcmd} app optin --app-id $APPID --from $ACCOUNT

# Succeed in clearing state for the app
${gcmd} app clear --app-id $APPID --from $ACCOUNT
