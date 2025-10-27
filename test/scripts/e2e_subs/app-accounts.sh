#!/bin/bash

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

# Create a smaller account so rewards won't change balances.
SMALL=$(${gcmd} account new | awk '{ print $6 }')
# Under one algo receives no rewards. Fund with extra to cover higher MinTxnFee costs.
# Must stay under 1,000,000 microAlgos to avoid earning rewards (which would break exact balance checks)
# This test uses 8 transactions from SMALL and requires minimum balance for app opt-in
# Min balance breakdown (app has 4 global byteslices, 1 local int):
# - Base: 100000
# - App creation (AppFlatParamsMinBalance): 100000
# - App opt-in (AppFlatOptInMinBalance): 100000
# - Global schema: 4 byteslices * (SchemaMinBalancePerEntry + SchemaBytesMinBalance) = 4 * 50000 = 200000
# - Local schema: 1 int * (SchemaMinBalancePerEntry + SchemaUintMinBalance) = 28500
# Total: 528500
NUM_TXNS=8
MIN_BALANCE_NEEDED=528500
# Calculate DEPOSIT amount needed for all withdrawal tests (20k + 10k + 18k + 2*fee + 100k min)
DEPOSIT_AMOUNT=$((20000 + 10000 + 18000 + 2*MIN_FEE + 100000))
SMALL_FUNDING=$((MIN_BALANCE_NEEDED + NUM_TXNS * MIN_FEE + DEPOSIT_AMOUNT + 50000))
if [ $SMALL_FUNDING -ge 1000000 ]; then
    SMALL_FUNDING=999000
fi
${gcmd} clerk send -a $SMALL_FUNDING -f "$ACCOUNT" -t "$SMALL"

function balance {
    acct=$1; shift
    goal account balance -a "$acct" | awk '{print $1}'
}

[ "$(balance "$ACCOUNT")" = $((1000000000000 - SMALL_FUNDING - MIN_FEE)) ]
[ "$(balance "$SMALL")" = $SMALL_FUNDING ]

APPID=$(${gcmd} app create --creator "${SMALL}" --approval-prog=${TEAL}/app-escrow.teal --global-byteslices 4 --global-ints 0 --local-byteslices 0 --local-ints 1  --clear-prog=${TEAL}/approve-all.teal | grep Created | awk '{ print $6 }')
[ "$(balance "$SMALL")" = $(($SMALL_FUNDING - MIN_FEE)) ] # app create fee

function appl {
    method=$1; shift
    ${gcmd} app call --app-id="$APPID" --from="$SMALL" --app-arg="str:$method" "$@"
}
function app-txid {
    # When app (call or optin) submits, this is how the txid is
    # printed.  Not in appl() because appl is also used with -o to
    # create tx
    grep -o -E 'txid [A-Z0-9]{52}' | cut -c 6- | head -1
}

APPACCT=$(python -c "import algosdk.encoding as e; print(e.encode_address(e.checksum(b'appID'+($APPID).to_bytes(8, 'big'))))")

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
[ "$(balance "$SMALL")" = $(($SMALL_FUNDING - 2*MIN_FEE)) ] # app create fee + opt-in fee

DEPOSIT=$DEPOSIT_AMOUNT  # Use the pre-calculated deposit amount
appl "deposit():void" -o "$T/deposit.tx"
payin $DEPOSIT -o "$T/pay1.tx"
cat "$T/deposit.tx" "$T/pay1.tx" | ${gcmd} clerk group -i - -o "$T/group.tx"
sign group
${gcmd} clerk rawsend -f "$T/group.stx"
[ "$(balance "$SMALL")" = $(($SMALL_FUNDING - 4*MIN_FEE - DEPOSIT)) ] # app create + opt-in + 2 group fees + deposit
[ "$(balance "$APPACCT")" = $DEPOSIT ]

# Withdraw 20,000 in app. Confirm that inner txn is visible to transaction API.
TXID=$(appl "withdraw(uint64):void" --app-arg="int:20000" | app-txid)
[ "$(rest "/v2/transactions/pending/$TXID" \
        | jq '.["inner-txns"][0].txn.txn.amt')" = 20000 ]
[ "$(rest "/v2/transactions/pending/$TXID?format=msgpack" | msgpacktool -d \
        | jq '.["inner-txns"][0].txn.txn.type')" = '"pay"' ]
# Now confirm it's in blocks API (this time in our internal form)
ROUND=$(rest "/v2/transactions/pending/$TXID" | jq '.["confirmed-round"]')
rest "/v2/blocks/$ROUND" | jq .block.txns[0].dt.itx

[ "$(balance "$SMALL")" = $(($SMALL_FUNDING - 5*MIN_FEE - DEPOSIT + 20000)) ]   # app create + opt-in + 2 group fees + deposit - 20k withdrawn + withdraw call fee
[ "$(balance "$APPACCT")" = $((DEPOSIT - 20000 - MIN_FEE)) ] # deposit - 20k withdrawn - inner txn fee paid by app account

appl "withdraw(uint64):void" --app-arg="int:10000" --fee $((MIN_FEE * 2))
[ "$(balance "$SMALL")" = $(($SMALL_FUNDING - 7*MIN_FEE - DEPOSIT + 30000)) ]   # app create + opt-in + 2 group + withdraw + fee-pooled withdraw + deposit - 30k withdrawn
[ "$(balance "$APPACCT")" = $((DEPOSIT - 20000 - MIN_FEE - 10000)) ] # deposit - 20k withdrawn - first inner txn fee - 10k withdrawn (fee credit used)

# Try to get app account below zero
# (By app logic, it's OK - enough was deposited, but fees have cut in)
WITHDRAW_FAIL=$((DEPOSIT - 20000 - MIN_FEE))  # Try to withdraw more than available
appl "withdraw(uint64):void" --app-arg="int:$WITHDRAW_FAIL" && exit 1
[ "$(balance "$SMALL")" = $(($SMALL_FUNDING - 7*MIN_FEE - DEPOSIT + 30000)) ]   # no change
[ "$(balance "$APPACCT")" = $((DEPOSIT - 20000 - MIN_FEE - 10000)) ] # no change

# Try to get app account below min balance by withdrawing too much
# At this point, app account should have just above 100k min balance
# Calculate a withdrawal that would drop below 100k
WITHDRAW_TOO_MUCH=$((DEPOSIT - 20000 - MIN_FEE - 10000 - 100000 + 1000))  # Try to leave less than 100k
appl "withdraw(uint64):void" --app-arg="int:$WITHDRAW_TOO_MUCH" && exit 1
[ "$(balance "$SMALL")" = $(($SMALL_FUNDING - 7*MIN_FEE - DEPOSIT + 30000)) ]   # no change
[ "$(balance "$APPACCT")" = $((DEPOSIT - 20000 - MIN_FEE - 10000)) ] # no change

# Try to get app account below min balance b/c of fee
WITHDRAW_FAIL_FEE=$((DEPOSIT - 20000 - MIN_FEE - 10000 - 100000 - MIN_FEE + 1))  # 1 more than allowed
appl "withdraw(uint64):void" --app-arg="int:$WITHDRAW_FAIL_FEE" && exit 1
[ "$(balance "$SMALL")" = $(($SMALL_FUNDING - 7*MIN_FEE - DEPOSIT + 30000)) ]   # no change
[ "$(balance "$APPACCT")" = $((DEPOSIT - 20000 - MIN_FEE - 10000)) ] # no change

# Show that it works AT exactly min balance
WITHDRAW_EXACT=$((DEPOSIT - 20000 - MIN_FEE - 10000 - 100000 - MIN_FEE))  # Leaves exactly 100k + fee
appl "withdraw(uint64):void" --app-arg="int:$WITHDRAW_EXACT"
[ "$(balance "$SMALL")" = $(($SMALL_FUNDING - 8*MIN_FEE - DEPOSIT + 30000 + WITHDRAW_EXACT)) ]   # All fees + all withdrawals
[ "$(balance "$APPACCT")" = 100000 ] # Exactly at min balance


date "+${scriptname} OK %Y%m%d_%H%M%S"
