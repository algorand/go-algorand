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

APPID=$(${gcmd} app create --creator "${SMALL}" --approval-prog=${TEAL}/app-escrow.teal --global-byteslices 4 --global-ints 0 --local-byteslices 0 --local-ints 1  --clear-prog=${TEAL}/approve-all.teal | grep Created | awk '{ print $6 }')
[ "$(balance "$SMALL")" = 999000 ] # 1000 fee

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
[ "$(balance "$SMALL")" = 998000 ] # 1000 fee

appl "deposit():void" -o "$T/deposit.tx"
payin 150000 -o "$T/pay1.tx"
cat "$T/deposit.tx" "$T/pay1.tx" | ${gcmd} clerk group -i - -o "$T/group.tx"
sign group
${gcmd} clerk rawsend -f "$T/group.stx"
[ "$(balance "$SMALL")" = 846000 ] # 2 fees, 150,000 deposited
[ "$(balance "$APPACCT")" = 150000 ]

# Withdraw 20,000 in app. Confirm that inner txn is visible to transaction API.
TXID=$(appl "withdraw(uint64):void" --app-arg="int:20000" | app-txid)
[ "$(rest "/v2/transactions/pending/$TXID" \
        | jq '.["inner-txns"][0].txn.txn.amt')" = 20000 ]
[ "$(rest "/v2/transactions/pending/$TXID?format=msgpack" | msgpacktool -d \
        | jq '.["inner-txns"][0].txn.txn.type')" = '"pay"' ]
# Now confirm it's in blocks API (this time in our internal form)
ROUND=$(rest "/v2/transactions/pending/$TXID" | jq '.["confirmed-round"]')
rest "/v2/blocks/$ROUND" | jq .block.txns[0].dt.itx

[ "$(balance "$SMALL")" = 865000 ]   # 1 fee, 20,000 withdrawn
[ "$(balance "$APPACCT")" = 129000 ] # 20k withdraw, fee paid by app account

appl "withdraw(uint64):void" --app-arg="int:10000" --fee 2000
[ "$(balance "$SMALL")" = 873000 ]   # 2000 fee, 10k withdrawn
[ "$(balance "$APPACCT")" = 119000 ] # 10k withdraw, fee credit used

# Try to get app account below zero
# (By app logic, it's OK - 150k was deposited, but fees have cut in)
appl "withdraw(uint64):void" --app-arg="int:120000" && exit 1
[ "$(balance "$SMALL")" = 873000 ]   # no change
[ "$(balance "$APPACCT")" = 119000 ] # no change

# Try to get app account below min balance by withdrawing too much
appl "withdraw(uint64):void" --app-arg="int:20000" && exit 1
[ "$(balance "$SMALL")" = 873000 ]   # no change
[ "$(balance "$APPACCT")" = 119000 ] # no change

# Try to get app account below min balance b/c of fee
appl "withdraw(uint64):void" --app-arg="int:18001" && exit 1
[ "$(balance "$SMALL")" = 873000 ]   # no change
[ "$(balance "$APPACCT")" = 119000 ] # no change

# Show that it works AT exactly min balance
appl "withdraw(uint64):void" --app-arg="int:18000"
[ "$(balance "$SMALL")" = 890000 ]   # +17k (18k - fee)
[ "$(balance "$APPACCT")" = 100000 ] # -19k (18k + fee)


date "+${scriptname} OK %Y%m%d_%H%M%S"
