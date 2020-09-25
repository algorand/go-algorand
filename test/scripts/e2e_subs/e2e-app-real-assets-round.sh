#!/bin/bash

date '+app-real-assets-round-test start %Y%m%d_%H%M%S'

set -e
set -x
set -o pipefail
export SHELLOPTS

WALLET=$1

# Directory of this bash program
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

gcmd="goal -w ${WALLET}"

ACCOUNT=$(${gcmd} account list|awk '{ print $3 }')

# Create an ASA in account
${gcmd} asset create --creator ${ACCOUNT} --name bogocoin --unitname bogo --total 1337
ASSET_ID=$(${gcmd} asset info --creator $ACCOUNT --unitname bogo|grep 'Asset ID'|awk '{ print $3 }')

# Create app that reads asset balance and checks asset details and checks round
ROUND=$(goal node status | grep 'Last committed' | awk '{ print $4 }')
TIMESTAMP=$(goal ledger block --strict ${ROUND} | jq .block.ts)
APP_ID=$(${gcmd} app create --creator ${ACCOUNT} --foreign-asset $ASSET_ID --app-arg "int:$ASSET_ID" --app-arg "int:1337" --app-arg "int:0" --app-arg "int:0" --app-arg "int:1337" --app-arg "str:bogo" --app-arg "int:$ROUND" --app-arg "int:$TIMESTAMP" --approval-prog ${DIR}/tealprogs/assetround.teal --global-byteslices 0 --global-ints 0 --local-byteslices 0 --local-ints 0 --clear-prog <(printf "#pragma version 2\nint 1") | grep Created | awk '{ print $6 }')

# Create another account, fund it, send it some asset
ACCOUNTB=$(${gcmd} account new|awk '{ print $6 }')
${gcmd} clerk send -a 1000000 -f $ACCOUNT -t $ACCOUNTB
${gcmd} asset send --assetid $ASSET_ID -a 0 -f $ACCOUNTB -t $ACCOUNTB
${gcmd} asset send --assetid $ASSET_ID -a 17 -f $ACCOUNT -t $ACCOUNTB

# Call app from account B, do some checks on asset balance
ROUND=$(goal node status | grep 'Last committed' | awk '{ print $4 }')
TIMESTAMP=$(goal ledger block --strict ${ROUND} | jq .block.ts)
${gcmd} app call --app-id $APP_ID --from $ACCOUNTB --foreign-asset $ASSET_ID --app-arg "int:$ASSET_ID" --app-arg "int:17" --app-arg "int:0" --app-arg "int:1" --app-arg "str:" --app-arg "str:" --app-arg "int:$ROUND" --app-arg "int:$TIMESTAMP"

# Freeze account B's holding
${gcmd} asset freeze --assetid $ASSET_ID --freeze=true --freezer $ACCOUNT --account $ACCOUNTB

# Check bit flipped
ROUND=$(goal node status | grep 'Last committed' | awk '{ print $4 }')
TIMESTAMP=$(goal ledger block --strict ${ROUND} | jq .block.ts)
${gcmd} app call --app-id $APP_ID --from $ACCOUNTB --foreign-asset $ASSET_ID --app-arg "int:$ASSET_ID" --app-arg "int:17" --app-arg "int:1" --app-arg "int:1" --app-arg "str:" --app-arg "str:" --app-arg "int:$ROUND" --app-arg "int:$TIMESTAMP"
