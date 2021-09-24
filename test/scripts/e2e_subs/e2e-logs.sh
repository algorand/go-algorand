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
# app create
TXID=$(${gcmd} app create --creator "${ACCOUNT}" --approval-prog=${TEAL}/logs.teal --global-byteslices 4 --global-ints 0 --local-byteslices 0 --local-ints 1  --clear-prog=${TEAL}/approve-all.teal | app-txid)
# log len
[ "$(rest "/v2/transactions/pending/$TXID" | jq '.logs | length')" = 32 ]
# log content
EXP=(B C D E F G H I J K L M N O P Q R S T U V W X Y Z [ \\ ] ^ _ \` a b )
i=0
for log in $(rest "/v2/transactions/pending/$TXID" | jq -r '.logs | .[]')
  do
    c=`echo -n "${log}" | base64 --decode`
    [ "$c" = "${EXP[i]}" ]
    ((i++))
  done

APPID=$(rest "/v2/transactions/pending/$TXID" | jq '.["application-index"]')
# app call
TXID=$(${gcmd} app call --app-id "${APPID}" --from "$ACCOUNT" | app-txid)
# log len
[ "$(rest "/v2/transactions/pending/$TXID" | jq '.logs | length')" = 32 ]
# log content
i=0
for log in $(rest "/v2/transactions/pending/$TXID" | jq -r '.logs | .[]')
  do
    c=`echo -n "${log}" | base64 --decode`
    [ "$c" = "${EXP[i]}" ]
    ((i++))
  done

date "+${scriptname} OK %Y%m%d_%H%M%S"