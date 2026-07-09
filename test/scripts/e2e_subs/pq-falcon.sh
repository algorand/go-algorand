#!/bin/bash

filename=$(basename "$0")
scriptname="${filename%.*}"
date "+${scriptname} start %Y%m%d_%H%M%S"

set -exo pipefail
export SHELLOPTS

WALLET=$1

gcmd="goal -w ${WALLET}"

ACCOUNT=$(${gcmd} account list|awk '{ print $3 }')

# Easier than prefixing all of the generated files.
cd "$TEMPDIR"

algokey pq generate -f pq.sk -p pq.pk > generate.out

PQMNEMONIC=$(grep 'PQ private key mnemonic:' < generate.out | sed 's/PQ private key mnemonic: //')
PQPUBKEY=$(grep 'PQ public key:' < generate.out | sed 's/PQ public key: //')
PQADDRESS=$(grep 'PQ address:' < generate.out | sed 's/PQ address: //')

echo "$PQMNEMONIC"
echo "$PQPUBKEY"
echo "$PQADDRESS"

# Restoring from mnemonic reproduces the key file.
algokey pq import -m "$PQMNEMONIC" -f pq-restored.sk
cmp pq.sk pq-restored.sk

# Fund pq account
${gcmd} clerk send -a 10000000 -f "${ACCOUNT}" -t "${PQADDRESS}"


# Send a pay back from the PQACCOUNT. `goal clerk` can not sign, since
# kmd does not understand PQ accounts.  `algokey` can.

## Show the usual min fee is insufficient
${gcmd} clerk send -a 5555 -f "${PQADDRESS}" -t "${ACCOUNT}" --fee 1000 -o low.tx
algokey pq sign -t low.tx -k pq.sk -o low-signed.tx
set +o pipefail
${gcmd} clerk rawsend -f low-signed.tx 2>&1 | grep "1mA fees is less than 3mA" || exit 1
set -o pipefail

## Show that 3000 min fee is sufficient
${gcmd} clerk send -a 6666 -f "${PQADDRESS}" -t "${ACCOUNT}" --fee 3000 -o enough.tx
algokey pq sign -t enough.tx -k pq.sk -o enough-signed.tx
${gcmd} clerk rawsend -f enough-signed.tx

BALANCE=$(${gcmd} account balance -a "${PQADDRESS}" | awk '{ print $1 }')
EXPECT=$((10000000 - 6666 - 3000))
if [ "$BALANCE" -ne "$EXPECT" ]; then
    date "+${scriptname} FAIL wanted balance=${EXPECT} but got ${BALANCE} %Y%m%d_%H%M%S"
    false
fi
