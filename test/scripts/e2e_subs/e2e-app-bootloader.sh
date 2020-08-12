#!/bin/bash

date '+app-bootloader-test start %Y%m%d_%H%M%S'

set -e
set -x
set -o pipefail
export SHELLOPTS

WALLET=$1

# Directory of this bash program
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

gcmd="goal -w ${WALLET}"

ACCOUNT=$(${gcmd} account list|awk '{ print $3 }')

# Compile target contract (we will upgrade ApprovalProgram and
# ClearStateProgram into this)
${gcmd} clerk compile ${DIR}/tealprogs/upgraded.teal -o ${TEMPDIR}/upgraded.tealc
TARGET_HASH=$(shasum -a 256 ${TEMPDIR}/upgraded.tealc | awk '{ print $1 }')

# Compile dummy, wrong contract
${gcmd} clerk compile ${DIR}/tealprogs/wrongupgrade.teal -o ${TEMPDIR}/wrongupgrade.tealc

# Copy template
cp ${DIR}/tealprogs/bootloader.teal.tmpl ${TEMPDIR}/bootloader.teal

# Substitute template values
sed -i"" -e "s/TMPL_APPROV_HASH/${TARGET_HASH}/g" ${TEMPDIR}/bootloader.teal
sed -i"" -e "s/TMPL_CLEARSTATE_HASH/${TARGET_HASH}/g" ${TEMPDIR}/bootloader.teal

# Create an app using filled-in bootloader template
printf '#pragma version 2\nint 1' > "${TEMPDIR}/int1.teal"
APPID=$(${gcmd} app create --creator ${ACCOUNT} --approval-prog ${TEMPDIR}/bootloader.teal --global-byteslices 1 --global-ints 0 --local-byteslices 0 --local-ints 0 --clear-prog "${TEMPDIR}/int1.teal" | grep Created | awk '{ print $6 }')

# Calling app without args and wrong OnCompletion should fail
EXPERROR='rejected by ApprovalProgram'
RES=$(${gcmd} app call --app-id $APPID --from $ACCOUNT 2>&1 || true)
if [[ $RES != *"${EXPERROR}"* ]]; then
    date '+app-bootloader-test FAIL call with no progs should fail %Y%m%d_%H%M%S'
    false
fi

# Calling app as an update but with wrong scripts should fail
EXPERROR='rejected by ApprovalProgram'
RES=$(${gcmd} app update --app-id $APPID --from $ACCOUNT --approval-prog-raw ${TEMPDIR}/wrongupgrade.tealc --clear-prog-raw ${TEMPDIR}/wrongupgrade.tealc 2>&1 || true)
if [[ $RES != *"${EXPERROR}"* ]]; then
    date '+app-bootloader-test FAIL update call with wrong progs should fail %Y%m%d_%H%M%S'
    false
fi

# Calling app as an update but with right scripts should succeed
${gcmd} app update --app-id $APPID --from $ACCOUNT --approval-prog-raw ${TEMPDIR}/upgraded.tealc --clear-prog-raw ${TEMPDIR}/upgraded.tealc

# Global state should be empty
RES=$(${gcmd} app read --guess-format --app-id $APPID --global | jq -r .foo.tb)
if [[ "$RES" != "null" ]]; then
    date '+app-bootloader-test FAIL unexpected global state after update %Y%m%d_%H%M%S'
    false
fi

# Calling app should succeed
${gcmd} app call --app-id $APPID --from $ACCOUNT

# Global state should now have 'foo': 'foo' key
RES=$(${gcmd} app read --guess-format --app-id $APPID --global | jq -r .foo.tb)
if [[ "$RES" != "foo" ]]; then
    date '+app-bootloader-test FAIL unexpected global state after update and call %Y%m%d_%H%M%S'
    false
fi
