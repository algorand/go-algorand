#!/usr/bin/env bash

# This is test for indexer ensuring app state
# Based on https://github.com/algorand/smart-contracts/tree/master/devrel/dexapp
#

date '+dex.sh start %Y%m%d_%H%M%S'

set -ex
set -o pipefail
export SHELLOPTS

# Directory of this bash program
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

WALLET=$1
gcmd="goal -w ${WALLET}"
ACCOUNT=$(${gcmd} account list|awk '{ print $3 }')

# create and fund accounts
ACCT_CREATOR=$(${gcmd} account new|awk '{ print $6 }')
ACCT_ACTOR=$(${gcmd} account new|awk '{ print $6 }')
$gcmd clerk send -a 10000000 -t "${ACCT_CREATOR}" -f "${ACCOUNT}"
$gcmd clerk send -a 10000000 -t "${ACCT_ACTOR}" -f "${ACCOUNT}"

echo "Created and funded accounts: creator ${ACCT_CREATOR}, actor ${ACCT_ACTOR}"

ASSETID=$(${gcmd} asset create --creator "${ACCT_CREATOR}" --total 100000 --unitname STOK  --decimals 0 | grep "Created asset with asset index" | rev | cut -d ' ' -f 1 | rev)
${gcmd} asset send -a 0 -f "${ACCT_ACTOR}" -t "${ACCT_ACTOR}"  --creator "${ACCT_CREATOR}" --assetid "${ASSETID}"
echo "Created asset ${ASSETID}"

APPID=$(${gcmd} app create --creator "${ACCT_CREATOR}" --approval-prog "${DIR}/tealprogs/dex.teal" --global-byteslices 1 --global-ints 0 --local-byteslices 0 --local-ints 16  --clear-prog <(printf '#pragma version 2\nint 1') | grep Created | awk '{ print $6 }')
echo "Created app ${APPID}"

${gcmd} app optin --app-id "$APPID" --from "$ACCT_ACTOR"

# Put order
ORDER="1-10000-1000000-10000-${ASSETID}"
${gcmd} app call --app-id "$APPID" --from "$ACCT_ACTOR" --app-arg "str:open" --app-arg "str:${ORDER}"

# Ensure the key is in place
VALUE=$(${gcmd} app read --app-id "$APPID" --from "$ACCT_ACTOR" --local | jq --arg key "$ORDER" '.[$key].ui')
if [ "$VALUE" -ne 1 ]; then
    date "+dex FAIL wanted value 1 but got ${VALUE} %Y%m%d_%H%M%S"
    false
fi

# Close order
${gcmd} app call --app-id "$APPID" --from "$ACCT_ACTOR" --app-arg "str:close" --app-arg "str:${ORDER}"

# Ensure the key is deleted
VALUE=$(${gcmd} app read --app-id "$APPID" --from "$ACCT_ACTOR" --local | jq --arg key "$ORDER" '.[$key].ui')
if [ "$VALUE" != "null" ]; then
    date "+dex FAIL wanted empty/null value but got ${VALUE} %Y%m%d_%H%M%S"
    false
fi

# Indexer still sees the $ORDER key but it is gone from the actual state
if [ -n "$INDEXER_URL" ]; then
    ENCODED=$(echo -n "$ORDER" | base64)
    curl "$INDEXER_URL/v2/accounts/${ACCT_ACTOR}?pretty" | jq --arg key "$ENCODED" -r '.account."apps-local-state"[]."key-value"[] | select(.key == $key)'
fi
