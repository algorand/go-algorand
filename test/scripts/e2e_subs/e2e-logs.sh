#!/bin/bash

filename=$(basename "$0")
scriptname="${filename%.*}"
date "+${scriptname} start %Y%m%d_%H%M%S"


my_dir="$(dirname "$0")"
source "$my_dir/rest.sh" "$@"
function rest() {
    curl -q -s -H "Authorization: Bearer $PUB_TOKEN" "$NET$1"
}

function app_txid {
    # When app (call or optin) submits, this is how the txid is
    # printed.
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
EXP=(B C D E F G H I J K L M N O P Q R S T U V W X Y Z \[ \\ \] ^ _ \` a b )

# app create
TXID=$(${gcmd} app create --creator "${ACCOUNT}" --approval-prog=${TEAL}/logs.teal --global-byteslices 4 --global-ints 0 --local-byteslices 0 --local-ints 1  --clear-prog=${TEAL}/approve-all.teal | app_txid)
response=$(rest "/v2/transactions/pending/$TXID")
# log len
[ "$(echo "$response" | jq '.logs | length')" = 32 ]
# log content
i=0
for log in $(echo "$response" | jq -r '.logs | .[]')
  do
    c=`echo -n "${log}" | base64 --decode`
    [ "$c" = "${EXP[i]}" ]
    i=$((i+1))
  done

# app call
APPID=$(echo "$response" | jq '.["application-index"]')
TXID=$(${gcmd} app call --app-id "${APPID}" --from "$ACCOUNT" | app_txid)
response=$(rest "/v2/transactions/pending/$TXID")
# log len
[ "$(echo "$response" | jq '.logs | length')" = 32 ]
# log content
i=0
for log in $(echo "$response" | jq -r '.logs | .[]')
  do
    c=`echo -n "${log}" | base64 --decode`
    [ "$c" = "${EXP[i]}" ]
    i=$((i+1))
  done

date "+${scriptname} OK %Y%m%d_%H%M%S"