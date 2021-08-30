#!/bin/bash

filename=$(basename "$0")
scriptname="${filename%.*}"
date "+${scriptname} start %Y%m%d_%H%M%S"

set -e
set -x
set -o pipefail
export SHELLOPTS

WALLET=$1

TEAL=test/scripts/e2e_subs/tealprogs

gcmd="goal -w ${WALLET}"

ACCOUNT=$(${gcmd} account list|awk '{ print $3 }')

APPID=$(${gcmd} app create --creator "$ACCOUNT" --approval-prog=${TEAL}/app-params.teal --clear-prog=${TEAL}/approve-all.teal --global-byteslices 1 --global-ints 2 --local-byteslices 3 --local-ints 4 --extra-pages 2 --app-arg "addr:$ACCOUNT" | grep Created | awk '{ print $6 }')

ACCOUNTB=$(${gcmd} account new|awk '{ print $6 }')
${gcmd} clerk send -f "$ACCOUNT" -t "$ACCOUNTB" -a 1000000

# Now call from a different account
${gcmd} app call --app-id="$APPID" --from="$ACCOUNTB" --app-arg "addr:$ACCOUNT"

# The below checks use quine.teal to test "app_params_get AppApprovalProgram"

# Verify "app_params_get AppApprovalProgram" works on create
APPID_2=$(${gcmd} app create --creator "$ACCOUNTB" --approval-prog=${TEAL}/quine.teal --clear-prog=${TEAL}/approve-all.teal --global-byteslices 0 --global-ints 0 --local-byteslices 0 --local-ints 0 --extra-pages 0 | grep Created | awk '{ print $6 }')

# Verify "app_params_get AppApprovalProgram" works on regular app call
${gcmd} app call --app-id="$APPID_2" --from="$ACCOUNTB"

# Verify "app_params_get AppApprovalProgram" works on update
${gcmd} app update --app-id="$APPID_2" --from="$ACCOUNTB" --approval-prog=${TEAL}/approve-all.teal --clear-prog=${TEAL}/approve-all.teal

date "+${scriptname} OK %Y%m%d_%H%M%S"
