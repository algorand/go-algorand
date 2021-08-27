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

APPID=$(${gcmd} app create --creator "${ACCOUNT}" --approval-prog=${TEAL}/app-escrow.teal --global-byteslices 4 --global-ints 0 --local-byteslices 0 --local-ints 1  --clear-prog=${TEAL}/approve-all.teal | grep Created | awk '{ print $6 }')

function call {
    method=$1; shift
    ${gcmd} app call --app-id="$APPID" --from="$ACCOUNT" --app-arg="str:$method" "$@"
}

APPACCT=$(python -c "import algosdk.encoding as e; print(e.encode_address(e.checksum(b'app'+($APPID).to_bytes(8, 'big'))))")

function balance {
    acct=$1; shift
    goal account balance -a "$acct" | awk '{print $1}'
}

[ "$(balance "$ACCOUNT")" = 999999999000 ]

function payin {
    amount=$1; shift
    ${gcmd} clerk send -f "$ACCOUNT" -t "$APPACCT" -a "$amount" "$@"
}

T=$TEMPDIR

function sign {
    ${gcmd} clerk sign -i "$T/$1.tx" -o "$T/$1.stx"
}

${gcmd} app optin --app-id "$APPID" --from "${ACCOUNT}"
[ "$(balance "$ACCOUNT")" = 999999998000 ]

call "deposit():void" -o "$T/deposit.tx"
payin 150000 -o "$T/pay1.tx"
cat "$T/deposit.tx" "$T/pay1.tx" | ${gcmd} clerk group -i - -o "$T/group.tx"
sign group
${gcmd} clerk rawsend -f "$T/group.stx"
[ "$(balance "$ACCOUNT")" = 999999846000 ] # 2 fees, 150,000 deposited
[ "$(balance "$APPACCT")" = 150000 ]

call "withdraw(uint64):void" --app-arg="int:20000"
[ "$(balance "$ACCOUNT")" = 999999865000 ] # 1 fee, 20,000 withdrawn
[ "$(balance "$APPACCT")" = 129000 ]       # 20k withdraw, fee paid by app account

call "withdraw(uint64):void" --app-arg="int:10000" --fee 2000
[ "$(balance "$ACCOUNT")" = 999999873000 ] # 2000 fee, 10k withdrawn
[ "$(balance "$APPACCT")" = 119000 ]       # 10k withdraw, fee credit used

# Try to get app account below zero
# (By app logic, it's OK - 150k was deposited, but fees have cut in)
call "withdraw(uint64):void" --app-arg="int:120000" && exit 1
[ "$(balance "$ACCOUNT")" = 999999873000 ] # no change
[ "$(balance "$APPACCT")" = 119000 ]       # no change

# Try to get app account below min balance by withdrawing too much
call "withdraw(uint64):void" --app-arg="int:20000" && exit 1
[ "$(balance "$ACCOUNT")" = 999999873000 ] # no change
[ "$(balance "$APPACCT")" = 119000 ]       # no change

# Try to get app account below min balance b/c of fee
call "withdraw(uint64):void" --app-arg="int:18001" && exit 1
[ "$(balance "$ACCOUNT")" = 999999873000 ] # no change
[ "$(balance "$APPACCT")" = 119000 ]       # no change

# Show that it works AT exactly min balance
call "withdraw(uint64):void" --app-arg="int:18000"
[ "$(balance "$ACCOUNT")" = 999999890000 ] # +17k (18k - fee)
[ "$(balance "$APPACCT")" = 100000 ]       # -19k (18k + fee)


date "+${scriptname} OK %Y%m%d_%H%M%S"
