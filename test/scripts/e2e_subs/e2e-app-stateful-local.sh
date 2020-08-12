#!/bin/bash

date '+app-stateful-local-test start %Y%m%d_%H%M%S'

set -e
set -x
set -o pipefail
export SHELLOPTS

WALLET=$1

# Directory of this bash program
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

gcmd="goal -w ${WALLET}"

ACCOUNT=$(${gcmd} account list|awk '{ print $3 }')

# Succeed in creating app that approves transactions with arg[0] == 'hello'
printf '#pragma version 2\nint 1' > "${TEMPDIR}/int1.teal"
APPID=$(${gcmd} app create --creator ${ACCOUNT} --approval-prog ${DIR}/tealprogs/loccheck.teal --global-byteslices 0 --global-ints 0 --local-byteslices 1 --local-ints 0 --app-arg "str:hello" --clear-prog "${TEMPDIR}/int1.teal" | grep Created | awk '{ print $6 }')

# Application call with no args should fail
EXPERROR='invalid ApplicationArgs index 0'
RES=$(${gcmd} app call --app-id $APPID --from $ACCOUNT 2>&1 || true)
if [[ $RES != *"${EXPERROR}"* ]]; then
    date '+app-create-test FAIL call with no args should fail %Y%m%d_%H%M%S'
    false
fi

# Application call with arg0 == "write" should fail before we opt in
RES=$(${gcmd} app call --app-id $APPID --app-arg "str:write" --from $ACCOUNT 2>&1 || true)
EXPERROR='not opted in'
if [[ $RES != *"${EXPERROR}"* ]]; then
    date '+app-create-test FAIL writing state should fail if account has not opted in %Y%m%d_%H%M%S'
    false
fi

# Should succeed to opt in with first arg hello
${gcmd} app optin --app-id $APPID --from $ACCOUNT --app-arg "str:hello"

# Write should now succeed
${gcmd} app call --app-id $APPID --app-arg "str:write" --from $ACCOUNT

# Check should now succeed with value "bar"
${gcmd} app call --app-id $APPID --app-arg "str:check" --app-arg "str:bar" --from $ACCOUNT

# Should succeed to close out with first arg hello
${gcmd} app closeout --app-id $APPID --from $ACCOUNT --app-arg "str:hello"

# Write/opt in in one tx should succeed
${gcmd} app optin --app-id $APPID --from $ACCOUNT --app-arg "str:write"

# Check should still succeed
${gcmd} app call --app-id $APPID --app-arg "str:check" --app-arg "str:bar" --from $ACCOUNT

# Delete application should still succeed
${gcmd} app delete --app-id $APPID --app-arg "str:hello" --from $ACCOUNT

# Check should fail since we can't find program to execute
RES=$(${gcmd} app call --app-id $APPID --app-arg "str:check" --app-arg "str:bar" --from $ACCOUNT 2>&1 || true)
EXPERROR='only clearing out is supported'
if [[ $RES != *"${EXPERROR}"* ]]; then
    date '+app-create-test FAIL app call should fail if app has been deleted %Y%m%d_%H%M%S'
    false
fi

# Clear should still succeed with arbitrary args
${gcmd} app clear --app-id $APPID --app-arg "str:asdf" --from $ACCOUNT
