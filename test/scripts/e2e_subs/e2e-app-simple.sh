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
APPID=$(${gcmd} app create --creator ${ACCOUNT} --approval-prog <(echo 'int 1') --clear-prog <(echo 'int 1') --global-byteslices 0 --global-ints 0 --local-byteslices 0 --local-ints 0 | grep Created | awk '{ print $6 }')

# Fail to create app if approval program rejects creation
RES=$(${gcmd} app create --creator ${ACCOUNT} --approval-prog <(echo 'int 0') --clear-prog <(echo 'int 1') --global-byteslices 0 --global-ints 0 --local-byteslices 0 --local-ints 0 2>&1 || true)
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
RES=$(${gcmd} app clear --app-id $APPID --from $ACCOUNT || true)
EXPERROR='not currently opted in'
if [[ $RES != *"${EXPERROR}"* ]]; then
    date '+app-create-test FAIL clearing state twice should fail %Y%m%d_%H%M%S'
    false
fi
