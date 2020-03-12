#!/bin/bash

date '+keyreg-teal-test start %Y%m%d_%H%M%S'

set -e
set -x
set -o pipefail
export SHELLOPTS

WALLET=$1

gcmd="goal -w ${WALLET}"

ACCOUNT=$(${gcmd} account list|awk '{ print $3 }')

# Succeed in creating app that approves all transactions
APPID=$(${gcmd} app create --creator ${ACCOUNT} --approval-prog <(echo 'int 1') --clear-prog <(echo 'int 1') | grep Created | awk '{ print $6 }')

# Fail to create app if approval program rejects creation
RES=$(${gcmd} app create --creator ${ACCOUNT} --approval-prog <(echo 'int 0') --clear-prog <(echo 'int 1') 2>&1 || true)
EXPERROR='rejected by ApprovalProgram'
if [[ $RES != *"${EXPERROR}"* ]]; then
    date '+app-create-test FAIL txn with failing approval prog should be rejected %Y%m%d_%H%M%S'
    false
fi

# Succeed in opting into the first app
${gcmd} app optin --app-id $APPID --from $ACCOUNT
