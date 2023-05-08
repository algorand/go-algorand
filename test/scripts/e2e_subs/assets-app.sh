#!/usr/bin/env bash
# TIMEOUT=300
#
# assets-app.sh and assets-app-b.sh both test the same TEAL app script, but in two separate parallelizeable chunks

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
MANAGER=$(${gcmd} account new|awk '{ print $6 }')

${gcmd} clerk send -a 100000000 -f ${CREATOR} -t ${ALICE} &
WA=$!
${gcmd} clerk send -a 100000000 -f ${CREATOR} -t ${BOB} &
WB=$!
${gcmd} clerk send -a 100000000 -f ${CREATOR} -t ${MANAGER} &
WC=$!
wait $WA
wait $WB
wait $WC

SUPPLY=10000000
XFER1=1000
XFER2=42
XFER3=99999
XFER4=11

APP_CREATED_STR='Created app with app index'
ERR_APP_CL_STR='only ClearState is supported for an application'
ERR_APP_NE_STR='application does not exist'
ERR_APP_OI_STR1='has not opted in to application'
ERR_APP_OI_STR2='not opted in to app'
ERR_APP_OI_STR3='is not currently opted in'
ERR_APP_REJ_STR1='transaction rejected by ApprovalProgram'
ERR_APP_REJ_STR2='err opcode executed'
ERR_APP_REJ_STR3='- would result negative'

### Basic reading, creation, deletion, transfers, and freezing

# create
APP_ID=$(${gcmd} app interact execute --header ${DIR}/asa.json --from $CREATOR --approval-prog ${DIR}/asa_approve.teal --clear-prog ${DIR}/asa_clear.teal create --manager $CREATOR --reserve $CREATOR --freezer $CREATOR --clawback $CREATOR --supply $SUPPLY | grep "$APP_CREATED_STR" | cut -d ' ' -f 6)

qcmd="${gcmd} app interact query --header ${DIR}/asa.json --app-id $APP_ID"
xcmd="${gcmd} app interact execute --header ${DIR}/asa.json --app-id $APP_ID"

date "+$scriptname created %Y%m%d_%H%M%S"

function assertContains {
    if [[ $1 != *"$2"* ]]; then
        echo "$1" does not contain "$2"
        date "+$scriptname FAIL $3 %Y%m%d_%H%M%S"
        false
    fi
}

# read global
RES=$(${qcmd} total-supply)
if [[ $RES != $SUPPLY ]]; then
    date "+$scriptname FAIL expected supply to be set to $SUPPLY %Y%m%d_%H%M%S"
    false
fi

RES=$(${qcmd} creator-balance)
if [[ $RES != $SUPPLY ]]; then
    date "+$scriptname FAIL expected creator to begin with $SUPPLY %Y%m%d_%H%M%S"
    false
fi

# read alice F
RES=$(${qcmd} --from $ALICE balance 2>&1 || true)
assertContains "$RES" "$ERR_APP_OI_STR1" "expected read of non-opted in account to fail"

# optin alice
${xcmd} --from $ALICE opt-in

# read alice
RES=$(${qcmd} --from $ALICE balance)
if [[ $RES != '0' ]]; then
    date "+$scriptname FAIL expected opted-in account to start with no balance %Y%m%d_%H%M%S"
    false
fi

RES=$(${qcmd} --from $ALICE frozen)
if [[ $RES != '0' ]]; then
    date "+$scriptname FAIL expected opted-in account to be non-frozen %Y%m%d_%H%M%S"
    false
fi

date "+$scriptname wat1 %Y%m%d_%H%M%S"

# xfer0 creator -> bob F
RES=$(${xcmd} --from $CREATOR transfer --receiver $BOB --amount $XFER1 2>&1 || true)
assertContains "$RES" "$ERR_APP_OI_STR2" "transfer succeeded on account which has not opted in"

# xfer1 (2) creator -> alice
${xcmd} --from $CREATOR transfer --receiver $ALICE --amount $XFER1 &
WA=$!
${xcmd} --from $CREATOR transfer --receiver $ALICE --amount $XFER1 &
WB=$!
wait $WA
wait $WB

# read alice
RES=$(${qcmd} --from $ALICE balance)
if [[ $RES != $(( $XFER1 + $XFER1 )) ]]; then
    date "+$scriptname FAIL transfer recipient does not have $XFER1 %Y%m%d_%H%M%S"
    false
fi

# destroy F
RES=$(${xcmd} --from $CREATOR destroy 2>&1 || true)
assertContains "$RES" "$ERR_APP_REJ_STR1" "should not be able to destroy asset while outstanding holdings exist"

# freeze
${xcmd} --from $CREATOR freeze --frozen 1 --target $ALICE

# xfer2 alice -> creator F
RES=$(${xcmd} --from $ALICE transfer --receiver $CREATOR --amount $XFER2 2>&1 || true)
assertContains "$RES" "$ERR_APP_REJ_STR2" "frozen account should not be able to send"

date "+$scriptname wat2 %Y%m%d_%H%M%S"

# xfer1 creator -> alice F
RES=$(${xcmd} --from $CREATOR transfer --receiver $ALICE --amount $XFER1 2>&1 || true)
assertContains "$RES" "$ERR_APP_REJ_STR2" "frozen account should not be able to receive"

# unfreeze
${xcmd} --from $CREATOR freeze --frozen 0 --target $ALICE

# xfer1 creator -> alice
${xcmd} --from $CREATOR transfer --receiver $ALICE --amount $XFER1

# xfer5 alice |-> alice F
RES=$(${xcmd} --from $ALICE close-out --close-to $ALICE 2>&1 || true)
assertContains "$RES" "$ERR_APP_REJ_STR1" "closing to self not permitted"

# optin bob
${xcmd} --from $BOB opt-in

# xfer3 alice -> bob overdraw F
RES=$(${xcmd} --from $ALICE transfer --receiver $BOB --amount $XFER3 2>&1 || true)
assertContains "$RES" "$ERR_APP_REJ_STR3" "overdraws are not permitted"

# xfer4 alice -> creator |-> bob
${xcmd} --from $ALICE close-out --receiver $CREATOR --amount $XFER4 --close-to $BOB

# xfer5 bob |-> alice F
RES=$(${xcmd} --from $BOB close-out --close-to $ALICE 2>&1 || true)
assertContains "$RES" "$ERR_APP_OI_STR2" "transfer succeeded on account which has closed out"

# optin alice
${xcmd} --from $ALICE opt-in

# xfer5 bob |-> alice
${xcmd} --from $BOB close-out --close-to $ALICE

# clear alice
${xcmd} --from $ALICE clear

# clear alice F
RES=$(${xcmd} --from $ALICE clear 2>&1 || true)
assertContains "$RES" "$ERR_APP_OI_STR3" "should not be able to clear asset holding twice"

# destroy
${xcmd} --from $CREATOR destroy

date "+$scriptname wat3 %Y%m%d_%H%M%S"

# destroy F
RES=$(${xcmd} --from $CREATOR destroy 2>&1 || true)
assertContains "$RES" "$ERR_APP_CL_STR" "second deletion of application should fail"

# optin alice F
RES=$(${xcmd} --from $ALICE opt-in 2>&1 || true)
assertContains "$RES" "$ERR_APP_CL_STR" "optin of deleted application should fail"

# read global F
RES=$(${qcmd} total-supply 2>&1 || true)
assertContains "$RES" "$ERR_APP_NE_STR" "read global of deleted application should fail"

date "+$scriptname OK %Y%m%d_%H%M%S"
