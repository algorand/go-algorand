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

APPID=$(${gcmd} app create --creator "$ACCOUNT" --approval-prog=${TEAL}/approve-all.teal --clear-prog=${TEAL}/approve-all.teal | grep Created | awk '{ print $6 }')

ACCOUNTB=$(${gcmd} account new|awk '{ print $6 }')
${gcmd} clerk send -f "$ACCOUNT" -t "$ACCOUNTB" -a 1000000

# Now call from a different account, reject-version=0 allows all
${gcmd} app call --app-id="$APPID" --from="$ACCOUNTB" --reject-version 0

# reject-version=1 allows because version is currently 0
${gcmd} app call --app-id="$APPID" --from="$ACCOUNTB" --reject-version 1

${gcmd} app update --app-id="$APPID" --from="$ACCOUNT" --approval-prog=${TEAL}/approve-all.teal --clear-prog=${TEAL}/approve-all.teal

# reject-version=0 allows all. This time do it by not specifying
${gcmd} app call --app-id="$APPID" --from="$ACCOUNTB"

# fail with rv=1, b/c version has incremented to 1
${gcmd} app call --app-id="$APPID" --from="$ACCOUNTB" --reject-version 1 && exit 1

# succeed with rv=2
${gcmd} app call --app-id="$APPID" --from="$ACCOUNTB" --reject-version 2


date "+${scriptname} OK %Y%m%d_%H%M%S"
