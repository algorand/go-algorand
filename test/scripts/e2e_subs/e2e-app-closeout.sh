#!/bin/bash

date '+app-closeout start %Y%m%d_%H%M%S'

set -e
set -x
set -o pipefail
export SHELLOPTS

WALLET=$1

# Directory of this bash program
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

gcmd="goal -w ${WALLET}"

ACCOUNT=$(${gcmd} account list|awk '{ print $3 }')
ACCOUNTB=$(${gcmd} account new|awk '{ print $6 }')

# Fund ACCOUNTB
${gcmd} clerk send -a 100000000 -f ${ACCOUNT} -t ${ACCOUNTB}

# Create an application that uses some global/local state
APPID=$(${gcmd} app create --creator ${ACCOUNT} --approval-prog <(printf '#pragma version 2\nint 1') --global-byteslices 1 --global-ints 1 --local-byteslices 1 --local-ints 1 --clear-prog <(printf '#pragma version 2\nint 1') | grep Created | awk '{ print $6 }')

# Should succeed to opt in
${gcmd} app optin --app-id $APPID --from $ACCOUNTB

# Closing out the account should fail
EXPERROR='outstanding applications'
RES=$(${gcmd} clerk send --from $ACCOUNTB --close-to $ACCOUNT --to $ACCOUNT -a 0 2>&1 || true)
if [[ $RES != *"${EXPERROR}"* ]]; then
    date '+app-closeout FAIL closing out account should fail if still opted in to app %Y%m%d_%H%M%S'
    false
fi

# Closing out of app should succeed
${gcmd} app closeout --app-id $APPID --from $ACCOUNTB

# Closing out the account should now succeed
${gcmd} clerk send --from $ACCOUNTB --close-to $ACCOUNT --to $ACCOUNT -a 0

# Fund ACCOUNTB again
${gcmd} clerk send -a 100000000 -f ${ACCOUNT} -t ${ACCOUNTB}

# Should succeed to opt again
${gcmd} app optin --app-id $APPID --from $ACCOUNTB

# Clearing out of app should succeed
${gcmd} app closeout --app-id $APPID --from $ACCOUNTB

# Closing out the account should still succeed
${gcmd} clerk send --from $ACCOUNTB --close-to $ACCOUNT --to $ACCOUNT -a 0

# Closing out the creator's account should fail
EXPERROR='outstanding created applications'
RES=$(${gcmd} clerk send --from $ACCOUNT --close-to $ACCOUNTB --to $ACCOUNTB -a 0 2>&1 || true)
if [[ $RES != *"${EXPERROR}"* ]]; then
    date '+app-closeout FAIL closing out account should fail if created app still exists %Y%m%d_%H%M%S'
    false
fi

# Deleting application should succeed
${gcmd} app delete --app-id $APPID --from $ACCOUNT

# Closing out the creator's account should now succeed
${gcmd} clerk send --from $ACCOUNT --close-to $ACCOUNTB --to $ACCOUNTB -a 0
