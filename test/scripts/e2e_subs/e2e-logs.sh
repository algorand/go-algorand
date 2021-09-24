#!/bin/bash

filename=$(basename "$0")
scriptname="${filename%.*}"
date "+${scriptname} start %Y%m%d_%H%M%S"


my_dir="$(dirname "$0")"
source "$my_dir/rest.sh" "$@"
function rest() {
    curl -q -s -H "Authorization: Bearer $PUB_TOKEN" "$NET$1"
}

function app-txid {
    # When app (call or optin) submits, this is how the txid is
    # printed.  Not in appl() because appl is also used with -o to
    # create tx
    grep -o -E 'txid [A-Z0-9]{52}' | cut -c 6- | head -1
}

set -e
set -x
set -o pipefail
export SHELLOPTS

WALLET=$1

TEAL=test/scripts/e2e_subs/tealprogs

gcmd="goal -w ${WALLET}"

ACCOUNT=$(${gcmd} account list|awk '{ print $3 }')

TXID=$(${gcmd} app create --creator "${ACCOUNT}" --approval-prog=${TEAL}/logs.teal --global-byteslices 4 --global-ints 0 --local-byteslices 0 --local-ints 1  --clear-prog=${TEAL}/approve-all.teal | app-txid)
#[ "$(rest "/v2/transactions/pending/$TXID" \
#        | jq '.["inner-txns"][0].txn.txn.amt')" = 20000 ]
logs= $(rest "/v2/transactions/pending/$TXID" | jq -r '.logs[]')
#print ${logs}
#[ "$(rest "/v2/transactions/pending/$TXID" | jq '.logs | length')" = 32 ]


date "+${scriptname} OK %Y%m%d_%H%M%S"