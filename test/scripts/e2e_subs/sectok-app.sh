#!/usr/bin/env bash
# TIMEOUT=380

filename=$(basename "$0")
scriptname="${filename%.*}"
date "+${scriptname} start %Y%m%d_%H%M%S"

set -ex
set -o pipefail
export SHELLOPTS

WALLET=$1
gcmd="goal -w ${WALLET}"

# Directory of helper TEAL programs
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )/tealprogs"

CREATOR=$(${gcmd} account list|awk '{ print $3 }')
ALICE=$(${gcmd} account new|awk '{ print $6 }')
BOB=$(${gcmd} account new|awk '{ print $6 }')
CAROL=$(${gcmd} account new|awk '{ print $6 }')
# MANAGER=$(${gcmd} account new|awk '{ print $6 }')

${gcmd} clerk send -a 100000000 -f ${CREATOR} -t ${ALICE} &
WA=$!
${gcmd} clerk send -a 100000000 -f ${CREATOR} -t ${BOB} &
WB=$!
${gcmd} clerk send -a 100000000 -f ${CREATOR} -t ${CAROL} &
WC=$!
wait $WA
wait $WB
wait $WC
# ${gcmd} clerk send -a 100000000 -f ${CREATOR} -t ${MANAGER}

SUPPLY=10000000
XFER1=1000
XFER2=42
XFER3=99999
XFER4=11
VERY_LATE=9999999999

APP_CREATED_STR='Created app with app index'
ERR_APP_CL_STR='only ClearState is supported for an application'
ERR_APP_NE_STR='application does not exist'
ERR_APP_OI_STR1='has not opted in to application'
ERR_APP_OI_STR2='not opted in to app'
ERR_APP_OI_STR3='is not currently opted in'
ERR_APP_REJ_STR1='transaction rejected by ApprovalProgram'
ERR_APP_REJ_STR2='err opcode executed'
ERR_APP_REJ_STR3='- would result negative'

# create
APP_ID=$(${gcmd} app interact execute --header ${DIR}/sectok.json --from $CREATOR --approval-prog ${DIR}/sectok_approve.teal --clear-prog ${DIR}/sectok_clear.teal create --token-params '{}' --total-supply $SUPPLY | grep "$APP_CREATED_STR" | cut -d ' ' -f 6)

xcmd="${gcmd} app interact execute --header ${DIR}/sectok.json --app-id ${APP_ID}"
qcmd="${gcmd} app interact query --header ${DIR}/sectok.json --app-id ${APP_ID}"

# read global
RES=$(${qcmd} total-supply)
if [[ $RES != $SUPPLY ]]; then
    date "+$scriptname FAIL expected supply to be set to $SUPPLY %Y%m%d_%H%M%S"
    false
fi

RES=$(${qcmd} reserve-supply)
if [[ $RES != $SUPPLY ]]; then
    date "+$scriptname FAIL expected reserve to begin with $SUPPLY %Y%m%d_%H%M%S"
    false
fi

function assertContains {
    if [[ $1 != *"$2"* ]]; then
        echo "$1" does not contain "'$2'"
        date "+$scriptname FAIL $3 %Y%m%d_%H%M%S"
        false
    fi
}

# read alice F
RES=$(${qcmd} --from $ALICE balance 2>&1 || true)
assertContains "$RES" "$ERR_APP_OI_STR1" "expected read of non-opted in account to fail"

# optin alice, bob, carol
${xcmd} --from $ALICE opt-in &
WA=$!
${xcmd} --from $BOB opt-in &
WB=$!
${xcmd} --from $CAROL opt-in &
WC=$!
wait $WA
wait $WB
wait $WC

RES=$(${qcmd} --from $ALICE transfer-group)
if [[ $RES != '0' ]]; then
    date "+$scriptname FAIL expected opt-in account to start with transfer group 0 %Y%m%d_%H%M%S"
    false
fi

RES=$(${qcmd} --from $ALICE balance)
if [[ $RES != '0' ]]; then
    date "+$scriptname FAIL expected opt-in account to start with 0 balance %Y%m%d_%H%M%S"
    false
fi

# assorted transfer-admin restrictions
RES=$(${xcmd} --from $CREATOR set-transfer-group --target $ALICE --transfer-group 1 2>&1 || true)
assertContains "$RES" "$ERR_APP_REJ_STR1" "contract-admins cannot set transfer groups"

RES=$(${xcmd} --from $CREATOR set-lock-until --target $ALICE --lock-until 1 2>&1 || true)
assertContains "$RES" "$ERR_APP_REJ_STR1" "contract-admins cannot set lock-until"

RES=$(${xcmd} --from $CREATOR set-max-balance --target $ALICE --max-balance $SUPPLY 2>&1 || true)
assertContains "$RES" "$ERR_APP_REJ_STR1" "contract-admins cannot set max balance"

RES=$(${xcmd} --from $ALICE set-transfer-group --target $ALICE --transfer-group 1 2>&1 || true)
assertContains "$RES" "$ERR_APP_REJ_STR1" "non-admins cannot set transfer groups"

RES=$(${xcmd} --from $ALICE set-lock-until --target $ALICE --lock-until 1 2>&1 || true)
assertContains "$RES" "$ERR_APP_REJ_STR1" "non-admins cannot set lock-until"

RES=$(${xcmd} --from $ALICE set-max-balance --target $ALICE --max-balance $SUPPLY 2>&1 || true)
assertContains "$RES" "$ERR_APP_REJ_STR1" "non-admins cannot set max balance"

# setting transfer-admin
RES=$(${xcmd} --from $ALICE freeze --target $ALICE --frozen 1 2>&1 || true)
assertContains "$RES" "$ERR_APP_REJ_STR1" "non-admins cannot freeze accounts"

RES=$(${xcmd} --from $ALICE set-transfer-admin --target $ALICE --status 1 2>&1 || true)
assertContains "$RES" "$ERR_APP_REJ_STR2" "non-admins cannot set transfer admin status"

${xcmd} --from $CREATOR set-transfer-admin --target $ALICE --status 1
${xcmd} --from $ALICE freeze --target $ALICE --frozen 1
${xcmd} --from $ALICE set-max-balance --target $ALICE --max-balance $SUPPLY
${xcmd} --from $CREATOR set-transfer-admin --target $ALICE --status 0

RES=$(${xcmd} --from $ALICE freeze --target $ALICE --frozen 0 2>&1 || true)
assertContains "$RES" "$ERR_APP_REJ_STR1" "non-admins (revoked) cannot freeze accounts"

# setting contract-admin
${xcmd} --from $CREATOR set-contract-admin --target $BOB --status 1
${xcmd} --from $BOB set-transfer-admin --target $ALICE --status 1
${xcmd} --from $CREATOR set-contract-admin --target $BOB --status 0

RES=$(${xcmd} --from $BOB set-transfer-admin --target $ALICE --status 0 2>&1 || true)
assertContains "$RES" "$ERR_APP_REJ_STR2" "non-admins cannot set transfer admin status"

RES=$(${xcmd} --from $BOB set-contract-admin --target $BOB --status 1 2>&1 || true)
assertContains "$RES" "$ERR_APP_REJ_STR2" "non-admins cannot set own contract admin status"

# minting/burning
${xcmd} --from $CREATOR mint --target $ALICE --amount $XFER1 &
WA=$!
${xcmd} --from $CREATOR mint --target $ALICE --amount $XFER1 &
WB=$!
wait $WA
wait $WB

RES=$(${qcmd} --from $ALICE balance)
if [[ $RES != $(( $XFER1 + $XFER1 )) ]]; then
    date "+$scriptname FAIL minting twice did not produce the correct balance %Y%m%d_%H%M%S"
    false
fi

RES=$(${qcmd} reserve-supply)
if [[ $RES != $(( $SUPPLY - $XFER1 - $XFER1 )) ]]; then
    date "+$scriptname FAIL minting twice did not produce the correct reserve balance %Y%m%d_%H%M%S"
    false
fi

${xcmd} --from $CREATOR burn --target $ALICE --amount $XFER1

RES=$(${qcmd} --from $ALICE balance)
if [[ $RES != $XFER1 ]]; then
    date "+$scriptname FAIL minting and then burning did not produce the correct balance %Y%m%d_%H%M%S"
    false
fi

${xcmd} --from $CREATOR burn --target $ALICE --amount $XFER1

# allowing transfers and transferring
${xcmd} --from $CREATOR mint --target $CAROL --amount $XFER1

RES=$(${xcmd} --from $CAROL transfer --receiver $BOB --amount $XFER2 2>&1 || true)
assertContains "$RES" "$ERR_APP_REJ_STR3" "new account should not be able to spend"

${xcmd} --from $ALICE set-max-balance --target $CAROL --max-balance $SUPPLY &
WA=$!
${xcmd} --from $ALICE set-max-balance --target $BOB --max-balance $SUPPLY &
WB=$!
wait $WA
wait $WB

${xcmd} --from $ALICE set-lock-until --target $CAROL --lock-until 1 &
WA=$!
${xcmd} --from $ALICE set-lock-until --target $BOB --lock-until 1 &
WB=$!
wait $WA
wait $WB

${xcmd} --from $ALICE set-transfer-group --target $CAROL --transfer-group 1 &
WA=$!
${xcmd} --from $ALICE set-transfer-group --target $BOB --transfer-group 2 &
WB=$!
wait $WA
wait $WB

RES=$(${xcmd} --from $CAROL transfer --receiver $BOB --amount $XFER2 2>&1 || true)
assertContains "$RES" "$ERR_APP_REJ_STR3" "no transfers allowed without transfer rules"

${xcmd} --from $ALICE set-transfer-rule --send-group 1 --receive-group 2 --lock-until 1
${xcmd} --from $CAROL transfer --receiver $BOB --amount $XFER2

RES=$(${xcmd} --from $BOB transfer --receiver $CAROL --amount $XFER2 2>&1 || true)
assertContains "$RES" "$ERR_APP_REJ_STR3" "reverse transfer (by group) should fail"

date "+$scriptname OK %Y%m%d_%H%M%S"
