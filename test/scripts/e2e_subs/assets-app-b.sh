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

### Reconfiguration, default-frozen, and clawback

date "+$scriptname wat4 %Y%m%d_%H%M%S"

# create frozen
APP_ID=$(${gcmd} app interact execute --header ${DIR}/asa.json --from $CREATOR --approval-prog ${DIR}/asa_approve.teal --clear-prog ${DIR}/asa_clear.teal create --manager $MANAGER --reserve $CREATOR --freezer $MANAGER --clawback $MANAGER --supply $SUPPLY --default-frozen 1 | grep "$APP_CREATED_STR" | cut -d ' ' -f 6)

qcmd="${gcmd} app interact query --header ${DIR}/asa.json --app-id $APP_ID"
xcmd="${gcmd} app interact execute --header ${DIR}/asa.json --app-id $APP_ID"

function assertContains {
    if [[ $1 != *"$2"* ]]; then
        echo "$1" does not contain "$2"
        date "+$scriptname FAIL $3 %Y%m%d_%H%M%S"
        false
    fi
}

# destroy bad manager F
RES=$(${xcmd} --from $CREATOR destroy 2>&1 || true)
assertContains "$RES" "$ERR_APP_REJ_STR1" "non-manager should not be able to delete asset"

# optin alice
${xcmd} --from $ALICE opt-in

# xfer1 F
RES=$(${xcmd} --from $CREATOR transfer --receiver $ALICE --amount $XFER1 2>&1 || true)
assertContains "$RES" "$ERR_APP_REJ_STR2" "frozen account should not be able to receive"

# bad unfreeze F
RES=$(${xcmd} --from $ALICE freeze --frozen 0 --target $ALICE 2>&1 || true)
assertContains "$RES" "$ERR_APP_REJ_STR1" "non-freezer should not be able to unfreeze account"

# set freezer alice
${xcmd} --from $MANAGER reconfigure --manager $MANAGER --reserve $CREATOR --freezer $ALICE --clawback $MANAGER

# unfreeze
${xcmd} --from $ALICE freeze --frozen 0 --target $ALICE

# xfer1
${xcmd} --from $CREATOR transfer --receiver $ALICE --amount $XFER1

# freeze
${xcmd} --from $ALICE freeze --frozen 1 --target $ALICE

# xfer1 F
RES=$(${xcmd} --from $CREATOR transfer --receiver $ALICE --amount $XFER1 2>&1 || true)
assertContains "$RES" "$ERR_APP_REJ_STR2" "re-frozen account should not be able to receive"

date "+$scriptname wat6 %Y%m%d_%H%M%S"

# closeout F
RES=$(${xcmd} --from $ALICE close-out --close-to $CREATOR 2>&1 || true)
assertContains "$RES" "$ERR_APP_REJ_STR2" "frozen account should not be able to closeout w/o clear"

# clear alice
${xcmd} --from $ALICE clear

# optin bob
${xcmd} --from $BOB opt-in

# clawback transfer
${xcmd} --from $MANAGER clawback --sender $CREATOR --receiver $BOB --amount $XFER1

# destroy F
RES=$(${xcmd} --from $MANAGER destroy 2>&1 || true)
assertContains "$RES" "$ERR_APP_REJ_STR1" "should not be able to delete asset while outstanding holdings exist"

# clawback
${xcmd} --from $MANAGER clawback --sender $BOB --receiver $CREATOR --amount $XFER1

# destroy
${xcmd} --from $MANAGER destroy

# clear bob
${xcmd} --from $BOB clear

date "+$scriptname OK %Y%m%d_%H%M%S"
