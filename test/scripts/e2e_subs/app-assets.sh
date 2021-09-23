#!/bin/bash

filename=$(basename "$0")
scriptname="${filename%.*}"
date "+${scriptname} start %Y%m%d_%H%M%S"


my_dir="$(dirname "$0")"
source "$my_dir/rest.sh" "$@"
function rest() {
    curl -q -s -H "Authorization: Bearer $PUB_TOKEN" "$NET$1"
}

set -e
set -x
set -o pipefail
export SHELLOPTS

WALLET=$1

TEAL=test/scripts/e2e_subs/tealprogs

gcmd="goal -w ${WALLET}"

ACCOUNT=$(${gcmd} account list|awk '{ print $3 }')
# Create a smaller account so rewards won't change balances.
SMALL=$(${gcmd} account new | awk '{ print $6 }')
# Under one algo receives no rewards
${gcmd} clerk send -a 1000000 -f "$ACCOUNT" -t "$SMALL"

function balance {
    acct=$1; shift
    goal account balance -a "$acct" | awk '{print $1}'
}

[ "$(balance "$ACCOUNT")" = 999998999000 ]
[ "$(balance "$SMALL")" =        1000000 ]

function held_assets {
    acct=$1;
    goal account info -a "$acct" | awk '/Held Assets:/,/Created Apps:/' | grep "ID*"
}

function asset_bal {
    acct=$1;
    goal account info -a "$acct" | awk '/Held Assets:/,/Created Apps:/' | grep "ID*" | awk -F'[, ]' '{print $7}'
}

function asset_ids {
    acct=$1;
    goal account info -a "$acct" | awk '/Held Assets:/,/Created Apps:/' | grep "ID*" | awk -F'[, ]' '{print $2}'
}
#
function assets {
    acct=$1;
    goal account info -a "$acct" | awk '/Held Assets:/,/Created Apps:/' | grep "ID*" | awk -F'[, ]' '{print $4}'
}

APPID=$(${gcmd} app create --creator "${SMALL}" --approval-prog=${TEAL}/assets-escrow.teal --global-byteslices 4 --global-ints 0 --local-byteslices 0 --local-ints 1  --clear-prog=${TEAL}/approve-all.teal | grep Created | awk '{ print $6 }')
[ "$(balance "$SMALL")" = 999000 ] # 1000 fee

function appl {
    method=$1; shift
    ${gcmd} app call --app-id="$APPID" --app-arg="str:$method" "$@"
}

function app-txid {
    # When app (call or optin) submits, this is how the txid is
    # printed.  Not in appl() because appl is also used with -o to
    # create tx
    grep -o -E 'txid [A-Z0-9]{52}' | cut -c 6- | head -1
}

function asset-id {
    grep -o -E 'index [A-Z0-9]+'| cut -c 7-
}

APPACCT=$(python -c "import algosdk.encoding as e; print(e.encode_address(e.checksum(b'appID'+($APPID).to_bytes(8, 'big'))))")
[ "$(balance "$SMALL")" = 999000 ] # 1000 fee

function asset-create {
    amount=$1; shift
    ${gcmd} asset create --creator "$SMALL" --total "$amount" --decimals 0 "$@"
}

function asset-deposit {
    amount=$1;shift
    ID=$1; shift
    ${gcmd} asset send -f "$SMALL" -t "$APPACCT" -a "$amount" --assetid "$ID" "$@"
}

function asset-optin {
    ${gcmd} asset send  -a 0 "$@"
}

function clawback_addr {
    grep -o -E 'Clawback address: [A-Z0-9]{58}' | awk '{print $3}'
}

T=$TEMPDIR

function sign {
    ${gcmd} clerk sign -i "$T/$1.tx" -o "$T/$1.stx"
}

TXID=$(${gcmd} app optin --app-id "$APPID" --from "${SMALL}" | app-txid)
# Rest succeeds, no stray inner-txn array
[ "$(rest "/v2/transactions/pending/$TXID" | jq '.["inner-txn"]')" == null ]
[ "$(balance "$SMALL")" = 998000 ] # 1000 fee

ASSETID=$(asset-create 1000000  --name "e2e" --unitname "e" | asset-id)
[ "$(balance "$SMALL")" = 997000 ] # 1000 fee

${gcmd} clerk send -a 1000000 -f "$ACCOUNT" -t "$APPACCT"
appl "optin():void" --app-arg="int:$ASSETID" --foreign-asset="$ASSETID" --from="$SMALL"
[ "$(balance "$APPACCT")" = 999000 ] # 1000 fee
[ "$(balance "$SMALL")" = 996000 ]

appl "deposit():void" -o "$T/deposit.tx" --from="$SMALL"
asset-deposit 1000 $ASSETID -o "$T/axfer1.tx"
cat "$T/deposit.tx" "$T/axfer1.tx" | ${gcmd} clerk group -i - -o "$T/group.tx"
sign group
${gcmd} clerk rawsend -f "$T/group.stx"

[ "$(asset_ids "$SMALL")" = $ASSETID ] # asset ID
[ "$(asset_bal "$SMALL")" = 999000 ]  # asset balance
[ "$(asset_ids "$APPACCT")" = $ASSETID ]
[ "$(asset_bal "$APPACCT")" = 1000 ]
[ "$(balance "$SMALL")" =        994000 ] # 2 fees
[ "$(balance "$APPACCT")" =      999000 ]


# Withdraw 100 in app. Confirm that inner txn is visible to transaction API.
TXID=$(appl "withdraw(uint64):void" --foreign-asset="$ASSETID" --app-arg="int:$ASSETID" --app-arg="int:100" --from="$SMALL" | app-txid)
[ "$(rest "/v2/transactions/pending/$TXID" \
        | jq '.["inner-txns"][0].txn.txn.aamt')" = 100 ]
[ "$(rest "/v2/transactions/pending/$TXID?format=msgpack" | msgpacktool -d \
        | jq '.["inner-txns"][0].txn.txn.type')" = '"axfer"' ]
# Now confirm it's in blocks API (this time in our internal form)
ROUND=$(rest "/v2/transactions/pending/$TXID" | jq '.["confirmed-round"]')
rest "/v2/blocks/$ROUND" | jq .block.txns[0].dt.itx

[ "$(asset_bal "$SMALL")" = 999100 ]   #  100 asset withdrawn
[ "$(asset_bal "$APPACCT")" = 900 ] # 100 asset withdrawn
[ "$(balance "$SMALL")" =        993000 ] # 1 fee
[ "$(balance "$APPACCT")" =        998000 ] # fee paid by app

appl "withdraw(uint64):void" --foreign-asset="$ASSETID" --app-arg="int:$ASSETID" --app-arg="int:100" --fee 2000 --from="$SMALL"
[ "$(asset_bal "$SMALL")" = 999200 ]   #  100 asset withdrawn
[ "$(balance "$SMALL")" = 991000 ]   # 2000 fee
[ "$(asset_bal "$APPACCT")" = 800 ] # 100 asset  withdrawn
[ "$(balance "$APPACCT")" = 998000 ] # fee credit used

# Try to withdraw too much
appl "withdraw(uint64):void" --foreign-asset="$ASSETID" --app-arg="int:$ASSETID" --app-arg="int:1000" --from="$SMALL"  && exit 1
[ "$(asset_bal "$SMALL")" = 999200 ]   # no change
[ "$(asset_bal "$APPACCT")" = 800 ]   # no change
[ "$(balance "$SMALL")" = 991000 ]
[ "$(balance "$APPACCT")" = 998000 ]

# Show that it works AT exact asset balance
appl "withdraw(uint64):void" --foreign-asset="$ASSETID" --app-arg="int:$ASSETID" --app-arg="int:800" --from="$SMALL"
[ "$(asset_bal "$SMALL")" = 1000000 ]
[ "$(asset_bal "$APPACCT")" = 0 ]
[ "$(balance "$SMALL")" = 990000 ]
[ "$(balance "$APPACCT")" = 997000 ]


# set appacct as clawback address on asset
${gcmd} asset config --manager $SMALL --assetid $ASSETID --new-clawback $APPACCT
cb_addr=$(${gcmd} asset info --assetid $ASSETID | clawback_addr)
[ "$cb_addr" = "$APPACCT" ] #app is set as clawback address

# app can transfer asset between accounts
USER=$(${gcmd} account new | awk '{ print $6 }') #new account
${gcmd} clerk send -a 1000000 -f "$ACCOUNT" -t "$USER" #fund account
asset-optin -f "$USER" -t "$USER"  --assetid "$ASSETID" #opt in to asset
# transfer asset from $SMALL to $USER
appl "transfer(uint64):void" --app-arg="int:$ASSETID" --app-arg="int:1000" --app-arg="addr:$USER" --foreign-asset="$ASSETID" --from="$SMALL" --app-account="$USER"
[ $(assets "$USER") = "e2e" ]
[ $(asset_bal "$USER") = 1000 ]
[ $(asset_bal "$SMALL") = 999000 ]
# transfer asset from $USER to $SMALL
appl "transfer(uint64):void" --app-arg="int:$ASSETID" --app-arg="int:100" --app-arg="addr:$SMALL" --foreign-asset="$ASSETID" --from="$USER" --app-account="$SMALL"
[ $(asset_bal "$USER") = 900 ]
[ $(asset_bal "$SMALL") = 999100 ]
# $USER does not have clawback auth
${gcmd} asset send -f "$SMALL" -t "$USER" -a "$amount" --assetid "$ASSETID" --clawback "$USER" && exit 1
#rekey $USER to "$APPACCT"
${gcmd} clerk send --from "$USER" --to "$USER" -a 0 --rekey-to "$APPACCT"

# opt in more assets
ASSETID2=$(asset-create 1000000  --name "alpha" --unitname "a"  | asset-id)
appl "optin():void" --app-arg="int:$ASSETID2" --foreign-asset="$ASSETID2" --from="$SMALL"
ASSETID3=$(asset-create 1000000  --name "beta" --unitname "b"  | asset-id)
appl "optin():void" --app-arg="int:$ASSETID3" --foreign-asset="$ASSETID3" --from="$SMALL"

IDs="
$ASSETID \n
$ASSETID2 \n
$ASSETID3 \n
"
[[ "$(held_assets "$APPACCT")" = $IDs ]]  # account has 3 assets

# opt out of assets
appl "close(uint64):void" --app-arg="int:$ASSETID2" --foreign-asset="$ASSETID2" --from="$SMALL"
IDs="
$ASSETID \n
$ASSETID3 \n
"
[[ "$(held_assets "$APPACCT")" = "$IDs" ]] # account has 2 assets
appl "close(uint64):void" --app-arg="int:$ASSETID" --foreign-asset="$ASSETID" --from="$SMALL"
appl "close(uint64):void" --app-arg="int:$ASSETID3" --foreign-asset="$ASSETID3" --from="$SMALL"
[[ "$(held_assets "$APPACCT")" = "" ]] # account has no assets


#app creates asset
#mint asset
#app afrz


date "+${scriptname} OK %Y%m%d_%H%M%S"
