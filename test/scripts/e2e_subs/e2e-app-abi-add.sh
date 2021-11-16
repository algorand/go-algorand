#!/bin/bash

date '+app-abi-add-test start %Y%m%d_%H%M%S'

set -e
set -x
set -o pipefail
export SHELLOPTS

WALLET=$1

# Directory of this bash program
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

gcmd="goal -w ${WALLET}"

GLOBAL_INTS=2
ACCOUNT=$(${gcmd} account list|awk '{ print $3 }')

printf '#pragma version 2\nint 1' > "${TEMPDIR}/simple.teal"
PROGRAM=($(${gcmd} clerk compile "${TEMPDIR}/simple.teal"))
APPID=$(${gcmd} app create --creator ${ACCOUNT} --approval-prog ${DIR}/tealprogs/app-abi-add-example.teal --clear-prog ${TEMPDIR}/simple.teal --global-byteslices 0 --global-ints ${GLOBAL_INTS} --local-byteslices 0 --local-ints 0 | grep Created | awk '{ print $6 }')

# Should succeed to opt in
${gcmd} app optin --app-id $APPID --from $ACCOUNT

# Call should now succeed
RES=$(${gcmd} app method --method "add(uint64,uint64)uint64" --arg 1 --arg 2 --app-id $APPID --from $ACCOUNT 2>&1 || true)
EXPECTED="method add(uint64,uint64)uint64 output: 3"
if [[ $RES != *"${EXPECTED}"* ]]; then
    date '+app-abi-add-test FAIL the application creation should not fail %Y%m%d_%H%M%S'
    false
fi

# Delete application should still succeed
${gcmd} app delete --app-id $APPID --from $ACCOUNT

# Clear should still succeed
${gcmd} app clear --app-id $APPID --from $ACCOUNT
