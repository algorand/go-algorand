#!/bin/bash

# This test is very similar to app-assets.sh, but uses --access pervasively.

filename=$(basename "$0")
scriptname="${filename%.*}"
date "+${scriptname} start %Y%m%d_%H%M%S"

my_dir="$(dirname "$0")"
source "$my_dir/rest.sh" "$@"

set -e
set -x
set -o pipefail
export SHELLOPTS

WALLET=$1

TEAL=test/scripts/e2e_subs/tealprogs

gcmd="goal -w ${WALLET}"

ACCOUNT=$(${gcmd} account list|awk '{ print $3 }')

# Get network's minimum fee
MIN_FEE=$(get_min_fee)
echo "Network MinFee: $MIN_FEE"

# This test uses approximately 24 transactions from SMALL account (similar to app-assets.sh)
NUM_TXNS=24
NEEDED_FOR_FEES=$((MIN_FEE * NUM_TXNS))

# SMALL's minimum balance at peak:
# - Base: 100000
# - App opt-in (with 1 local int): 128500 (100000 + 25000 + 3500 for schema)
# - 2 created assets (each with auto opt-in): 400000 (2 * 200000)
# - Total: 628500
MAX_MIN_BALANCE=628500

# Total amount needed: fees + min balance
TOTAL_NEEDED=$((NEEDED_FOR_FEES + MAX_MIN_BALANCE + MIN_FEE * 3))

# Fund with at least 2 Algos to ensure enough for high MIN_FEE scenarios
# Note: Account will earn rewards (RewardUnit = 1,000,000), so balance checks must be tolerant
SMALL_FUNDING=$((TOTAL_NEEDED > 2000000 ? TOTAL_NEEDED : 2000000))

# Tolerance for balance checks (to account for rewards earned)
# Allow up to 5000 microAlgos tolerance per balance check
BALANCE_TOLERANCE=5000
SMALL=$(${gcmd} account new | awk '{ print $6 }')
${gcmd} clerk send -a $SMALL_FUNDING -f "$ACCOUNT" -t "$SMALL"

function balance {
    acct=$1; shift
    goal account balance -a "$acct" | awk '{print $1}'
}

# Check if balance is within tolerance of expected value
# Usage: check_balance <account> <expected_balance>
# Allows BALANCE_TOLERANCE above expected (for rewards) but exact match below
function check_balance {
    local acct=$1
    local expected=$2
    local actual
    actual=$(balance "$acct")
    local diff=$((actual - expected))

    if [ $diff -lt 0 ] || [ $diff -gt $BALANCE_TOLERANCE ]; then
        echo "ERROR: Balance check failed for $acct"
        echo "  Expected: $expected (tolerance: +0 to +$BALANCE_TOLERANCE)"
        echo "  Actual:   $actual (diff: $diff)"
        return 1
    fi
    return 0
}

check_balance "$ACCOUNT" $((1000000000000 - $SMALL_FUNDING - MIN_FEE))
check_balance "$SMALL"        $SMALL_FUNDING

function created_assets {
    acct=$1;
    goal account info -a "$acct" | awk '/Created Assets:/,/Held Assets:/' | grep "ID*" | awk -F'[, ]' '{print $4}'
}

function created_supply {
    acct=$1;
    goal account info -a "$acct" | awk '/Created Assets:/,/Held Assets:/' | grep "ID*" | awk -F'[, ]' '{print $7}'
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

APPID=$(${gcmd} app create --creator "${SMALL}" --approval-prog=${TEAL}/assets-escrow9.teal --global-byteslices 4 --global-ints 0 --local-byteslices 0 --local-ints 1  --clear-prog=<(printf '#pragma version 9\nint 1') | grep Created | awk '{ print $6 }')
check_balance "$SMALL" $((SMALL_FUNDING - MIN_FEE))

# Use --access on all app calls
function appl {
    method=$1; shift
    ${gcmd} app call --app-id="$APPID" --app-arg="str:$method" --access "$@"
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
EXAMPLE_URL="http://example.com"
function asset-create {
    amount=$1; shift
    ${gcmd} asset create --creator "$SMALL" --total "$amount" --decimals 0 "$@" --asseturl "$EXAMPLE_URL"
}

function asset-deposit {
    amount=$1;shift
    ID=$1; shift
    ${gcmd} asset send -f "$SMALL" -t "$APPACCT" -a "$amount" --assetid "$ID" "$@"
}

function asset-optin {
    ${gcmd} asset optin "$@"
}

function clawback_addr {
    grep -o -E 'Clawback address: [A-Z0-9]{58}' | awk '{print $3}'
}

function asset_url {
    grep -o -E 'URL:.*'|awk '{print $2}'
}

function payin {
    amount=$1; shift
    ${gcmd} clerk send -f "$SMALL" -t "$APPACCT" -a "$amount" "$@"
}

T=$TEMPDIR

function sign {
    ${gcmd} clerk sign -i "$T/$1.tx" -o "$T/$1.stx"
}

TXID=$(${gcmd} app optin --app-id "$APPID" --from "${SMALL}" | app-txid)
# Rest succeeds, no stray inner-txn array
[ "$(rest "/v2/transactions/pending/$TXID" | jq '.["inner-txn"]')" == null ]
check_balance "$SMALL" $((SMALL_FUNDING - MIN_FEE * 2))

ASSETID=$(asset-create 1000000  --name "e2e" --unitname "e" | asset-id)
check_balance "$SMALL" $((SMALL_FUNDING - MIN_FEE * 3))

${gcmd} clerk send -a 999000 -f "$ACCOUNT" -t "$APPACCT"
! appl "optin(uint64):void" --app-arg "int:$ASSETID" --foreign-asset="$ASSETID" --from="$SMALL" || exit 1
appl "optin(uint64):void" --app-arg "int:$ASSETID" --foreign-asset="$ASSETID" --from="$SMALL" --holding "$ASSETID+app($APPID)"
check_balance "$APPACCT" $((999000 - MIN_FEE))
check_balance "$SMALL" $((SMALL_FUNDING - MIN_FEE * 4))

# Deposit is exactly like app-assets.sh only sender's local state is accessed
appl "deposit():void" -o "$T/deposit.tx" --from="$SMALL"
asset-deposit 1000 $ASSETID -o "$T/axfer1.tx"
cat "$T/deposit.tx" "$T/axfer1.tx" | ${gcmd} clerk group -i - -o "$T/group.tx"
sign group
${gcmd} clerk rawsend -f "$T/group.stx"

[ "$(asset_ids "$SMALL")" = $ASSETID ] # asset ID
[ "$(asset_bal "$SMALL")" = 999000 ]  # asset balance
[ "$(asset_ids "$APPACCT")" = $ASSETID ]
[ "$(asset_bal "$APPACCT")" = 1000 ]
check_balance "$SMALL" $((SMALL_FUNDING - MIN_FEE * 6))
check_balance "$APPACCT" $((999000 - MIN_FEE))

# Withdraw 100 in app. Confirm that inner txn is visible to transaction API.
! appl "withdraw(uint64,uint64):void" --app-arg="int:$ASSETID" --app-arg="int:100" --foreign-asset="$ASSETID" --from="$SMALL" || exit 1
WITHDRAW=("withdraw(uint64,uint64):void" --app-arg="int:$ASSETID" --from="$SMALL" --holding "$ASSETID+app($APPID),$ASSETID+$SMALL")
TXID=$(appl "${WITHDRAW[@]}" --app-arg="int:100" | app-txid)
[ "$(rest "/v2/transactions/pending/$TXID" \
        | jq '.["inner-txns"][0].txn.txn.aamt')" = 100 ]
[ "$(rest "/v2/transactions/pending/$TXID?format=msgpack" | msgpacktool -d \
        | jq '.["inner-txns"][0].txn.txn.type')" = '"axfer"' ]
# Now confirm it's in blocks API (this time in our internal form)
ROUND=$(rest "/v2/transactions/pending/$TXID" | jq '.["confirmed-round"]')
rest "/v2/blocks/$ROUND" | jq .block.txns[0].dt.itx

[ "$(asset_bal "$SMALL")" = 999100 ] # 100 asset withdrawn
[ "$(asset_bal "$APPACCT")" = 900 ]  # 100 asset withdrawn
check_balance "$SMALL" $((SMALL_FUNDING - MIN_FEE * 7))
check_balance "$APPACCT" $((999000 - MIN_FEE * 2))

appl "${WITHDRAW[@]}" --app-arg="int:100" --fee $((MIN_FEE * 2))
[ "$(asset_bal "$SMALL")" = 999200 ] # 100 asset withdrawn
[ "$(asset_bal "$APPACCT")" = 800 ]  # 100 asset withdrawn
check_balance "$SMALL" $((SMALL_FUNDING - MIN_FEE * 9))
check_balance "$APPACCT" $((999000 - MIN_FEE * 2))

# Try to withdraw too much
! appl "${WITHDRAW[@]}" --app-arg="int:1000" || exit 1
[ "$(asset_bal "$SMALL")" = 999200 ] # no changes
[ "$(asset_bal "$APPACCT")" = 800 ]
check_balance "$SMALL" $((SMALL_FUNDING - MIN_FEE * 9))
check_balance "$APPACCT" $((999000 - MIN_FEE * 2))

# Show that it works AT exact asset balance
appl "${WITHDRAW[@]}" --app-arg="int:800"
[ "$(asset_bal "$SMALL")" = 1000000 ]
[ "$(asset_bal "$APPACCT")" = 0 ]
check_balance "$SMALL" $((SMALL_FUNDING - MIN_FEE * 10))
check_balance "$APPACCT" $((999000 - MIN_FEE * 3))

USER=$(${gcmd} account new | awk '{ print $6 }') #new account
${gcmd} clerk send -a 999000 -f "$ACCOUNT" -t "$USER" #fund account
asset-optin --assetid "$ASSETID" -a $USER #opt in to asset
# SET $USER as clawback address
${gcmd} asset config --manager $SMALL --assetid $ASSETID --new-clawback $USER
cb_addr=$(${gcmd} asset info --assetid $ASSETID | clawback_addr)
[ "$cb_addr" = "$USER" ]
url=$(${gcmd} asset info --assetid $ASSETID | asset_url)
[ "$url" = "$EXAMPLE_URL" ]
${gcmd} asset send -f "$SMALL" -t "$USER" -a "1000" --assetid "$ASSETID" --clawback "$USER"
[ $(asset_bal "$USER") = 1000 ]
[ $(asset_bal "$SMALL") = 999000 ]
# rekey $USER to "$APPACCT"
${gcmd} clerk send --from "$USER" --to "$USER" -a 0 --rekey-to "$APPACCT"
# $USER should still have clawback auth. should have been authorized by "$APPACCT"
${gcmd} asset send -f "$SMALL" -t "$USER" -a "1000" --assetid "$ASSETID" --clawback "$USER" && exit 1

USER2=$(${gcmd} account new | awk '{ print $6 }') #new account
${gcmd} clerk send -a 999000 -f "$ACCOUNT" -t "$USER2" #fund account
asset-optin --assetid "$ASSETID" -a $USER2 #opt in to asset
# set $APPACCT as clawback address on asset
${gcmd} asset config --manager $SMALL --assetid $ASSETID --new-clawback $APPACCT
cb_addr=$(${gcmd} asset info --assetid $ASSETID | clawback_addr)
[ "$cb_addr" = "$APPACCT" ] #app is set as clawback address
# transfer asset from $SMALL to $USER
# With just the accounts and asset, won't work b/c the holdings are required
RES=$(appl "transfer(uint64,uint64,address):void" --from="$SMALL" \
     --app-arg="int:$ASSETID" --app-arg="int:1000" --app-arg="addr:$USER2" \
     --foreign-asset="$ASSETID" --app-account="$USER2" 2>&1) && {
    date '+app-assets-access FAIL transfer should fail without explicit holding %Y%m%d_%H%M%S'
    exit 1
}
# allowsAssetTransfer checks the AssetReceiver before AssetSender, so we get that error.
[[ $RES == *"unavailable Holding $ASSETID+$USER2"* ]] || exit 1

# Need access to both holdings.
appl "transfer(uint64,uint64,address):void" \
     --from="$SMALL"  --holding="$ASSETID+$SMALL" \
     --app-arg="int:$ASSETID" --app-arg="int:1000" \
     --app-arg="addr:$USER2" --holding="$ASSETID+$USER2"


[ $(asset_bal "$USER2") = 1000 ]
[ $(asset_bal "$SMALL") = 998000 ]
# transfer asset from $USER2 to $SMALL (this invocation tries to just
# specify the asset and the recipient account) It fails because with
# --access, cross-products are not implicitly available.
RES=$(appl "transfer(uint64,uint64,address):void" --from="$USER2" \
     --app-arg="int:$ASSETID" --app-arg="int:100" --foreign-asset="$ASSETID" \
     --app-arg="addr:$SMALL" --app-account="$SMALL" 2>&1) && {
    date '+app-assets FAIL transfer using --access should fail without explicit holding %Y%m%d_%H%M%S'
    exit 1
}
[[ $RES == *"unavailable Holding"* ]] || exit 1

appl "transfer(uint64,uint64,address):void" --from="$USER2" --holding="$ASSETID+$USER2" \
     --app-arg="int:$ASSETID" --app-arg="int:100" \
     --app-arg="addr:$SMALL" --holding="$ASSETID+$SMALL"

[ $(asset_bal "$USER2") = 900 ]
[ $(asset_bal "$SMALL") = 998100 ]

# opt in more assets. --holding for the app/asset is needed
ASSETID2=$(asset-create 1000000  --name "alpha" --unitname "a" | asset-id)
appl "optin(uint64):void" --app-arg "int:$ASSETID2" --foreign-asset="$ASSETID2" --from="$SMALL" --holding "$ASSETID2+app($APPID)"
ASSETID3=$(asset-create 1000000  --name "beta" --unitname "b" | asset-id)
appl "optin(uint64):void" --app-arg "int:$ASSETID3" --foreign-asset="$ASSETID3" --from="$SMALL" --holding "$ASSETID3+app($APPID)"

IDs="$ASSETID
$ASSETID2
$ASSETID3"
[[ "$(asset_ids "$APPACCT")" = $IDs ]] || exit 1  # account has 3 assets

# opt out of assets
RES=$(appl "close(uint64):void" --from="$SMALL" --app-arg "int:$ASSETID2" --foreign-asset="$ASSETID2" 2>&1) && {
    date '+app-assets FAIL close using --access should fail without explicit app holding %Y%m%d_%H%M%S'
    exit 1
}
[[ $RES == *"unavailable Holding $ASSETID2+$APPACCT"* ]] || exit 1 # app can't close itself unless its holding is available

# add that holding, but still not enough...
RES=$(appl "close(uint64):void" --from="$SMALL" --app-arg "int:$ASSETID2" --holding="$ASSETID2+$APPACCT" 2>&1) && {
    date '+app-assets FAIL close using --access should fail without explicit sender holding %Y%m%d_%H%M%S'
    exit 1
}
[[ $RES == *"unavailable Holding $ASSETID2+$SMALL"* ]] || exit 1   # app closes to sender, so needs that holding too

appl "close(uint64):void" --from="$SMALL" --app-arg "int:$ASSETID2" \
     --holding="$ASSETID2+$APPACCT,$ASSETID2+$SMALL"
IDs="$ASSETID
$ASSETID3"
[[ "$(asset_ids "$APPACCT")" = $IDs ]] || exit 1 # account has 2 assets
appl "close(uint64):void" --from="$SMALL" --app-arg "int:$ASSETID" \
     --holding="$ASSETID+$APPACCT,$ASSETID+$SMALL"
appl "close(uint64):void" --from="$SMALL" --app-arg "int:$ASSETID3" \
     --holding="$ASSETID3+$APPACCT" --holding="$ASSETID3+$SMALL"
[[ "$(asset_ids "$APPACCT")" = "" ]] || exit 1 # account has no assets

# app creates asset
appl "create(uint64):void" --app-arg="int:1000000" --from="$SMALL"
[ "$(created_assets "$APPACCT")" = "X" ]
[ "$(created_supply "$APPACCT")" = 1000000 ]

# mint asset
APPASSETID=$(asset_ids "$APPACCT")
asset-optin --assetid "$APPASSETID" -a $SMALL #opt in to asset
appl "mint(uint64):void" --from="$SMALL" --app-arg "int:$APPASSETID" \
     --holding="$APPASSETID+app($APPID)" --holding="$APPASSETID+$SMALL" \
     -o "$T/mint.tx"
payin 1000 -o "$T/pay1.tx"
cat "$T/mint.tx" "$T/pay1.tx" | ${gcmd} clerk group -i - -o "$T/group.tx"
sign group
${gcmd} clerk rawsend -f "$T/group.stx"

IDs="$ASSETID
$ASSETID2
$ASSETID3
$APPASSETID"
[[ "$(asset_ids "$SMALL")" = $IDs ]] || exit 1 # has new asset
[ "$(asset_bal "$SMALL" | awk 'FNR==4{print $0}')" =  1000 ] # correct balances
[ "$(asset_bal "$APPACCT")" = 999000 ] # 1k sent

# freeze asset
RES=$(appl "freeze(uint64,bool):void" --from="$SMALL" --app-arg="int:$APPASSETID" --app-arg="int:1" --foreign-asset="$APPASSETID" 2>&1) && {
    date '+app-assets FAIL freeze using --access should fail without explicit sender holding %Y%m%d_%H%M%S'
    exit 1
}
[[ $RES == *"unavailable Holding $APPASSETID+$SMALL"* ]] || exit 1
appl "freeze(uint64,bool):void" --from="$SMALL" --app-arg="int:$APPASSETID" --app-arg="int:1" --holding="$APPASSETID+$SMALL"

# fail since asset is frozen on $SMALL
appl "mint(uint64):void" --from="$SMALL" --app-arg="int:$APPASSETID" \
     --holding="$APPASSETID+app($APPID)" --holding="$APPASSETID+$SMALL" \
      -o "$T/mint.tx"
payin 1000 -o "$T/pay1.tx"
cat "$T/mint.tx" "$T/pay1.tx" | ${gcmd} clerk group -i - -o "$T/group.tx"
sign group
${gcmd} clerk rawsend -f "$T/group.stx" && exit 1 # fail or exit


# unfreeze asset
appl "freeze(uint64,bool):void" --app-arg="int:$APPASSETID" --app-arg="int:0" --holding="$APPASSETID+$SMALL" --from="$SMALL"
# try to resend that same group
${gcmd} clerk rawsend -f "$T/group.stx"                     # try again
[ "$(asset_bal "$SMALL" | awk 'FNR==4{print $0}')" = 2000 ] # minted 1000

date "+${scriptname} OK %Y%m%d_%H%M%S"
