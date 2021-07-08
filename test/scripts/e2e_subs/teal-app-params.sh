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

APPID=$(${gcmd} app create --creator "${ACCOUNT}" --approval-prog=${TEAL}/app-params.teal  --clear-prog=${TEAL}/approve-all.teal --global-byteslices 1 --global-ints 2 --local-byteslices 3 --local-ints 4 --extra-pages 2 | grep Created | awk '{ print $6 }')

ACCOUNTB=$(${gcmd} account new|awk '{ print $6 }')
${gcmd} clerk send -f "$ACCOUNT" -t "$ACCOUNTB" -a 1000000

# Now call from a different account
${gcmd} app call --app-id="$APPID" --from="$ACCOUNTB"



date "+${scriptname} OK %Y%m%d_%H%M%S"
