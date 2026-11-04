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

echo "int 1" > pq-true.teal
${gcmd} clerk compile pq-true.teal -o pq-true.tok

# Fund accounts below one reward unit to avoid unexpected balance drift from rewards.
FUNDING=900000

algokey salted generate -S falcon-1024 -k pq.sk > generate.out

PQMNEMONIC=$(grep 'Private key mnemonic:' < generate.out | sed 's/Private key mnemonic: //')
PQPUBKEY=$(grep 'Public key:' < generate.out | sed 's/Public key: //')
PQADDRESS=$(grep 'Address:' < generate.out | sed 's/Address: //')

echo "$PQMNEMONIC"
echo "$PQPUBKEY"
echo "$PQADDRESS"

# Restoring from mnemonic reproduces the key file.
algokey salted import -m "$PQMNEMONIC" -S falcon-1024 -k pq-restored.sk
cmp pq.sk pq-restored.sk

${gcmd} clerk send -a "${FUNDING}" -f "${ACCOUNT}" -t "${PQADDRESS}"


# Send a pay back from the PQACCOUNT. `goal clerk` can not sign, since
# kmd does not understand PQ accounts.  `algokey` can.

## Show the usual min fee is insufficient
${gcmd} clerk send -a 5555 -f "${PQADDRESS}" -t "${ACCOUNT}" --fee 1000 -o low.tx
algokey salted sign -t low.tx -k pq.sk -o low-signed.tx
set +o pipefail
${gcmd} clerk rawsend -f low-signed.tx 2>&1 | grep "1mA fees is less than 3mA" || exit 1
set -o pipefail

## Show that 3000 min fee is sufficient
${gcmd} clerk send -a 6666 -f "${PQADDRESS}" -t "${ACCOUNT}" --fee 3000 -o enough.tx
algokey salted sign -t enough.tx -k pq.sk -o enough-signed.tx
${gcmd} clerk rawsend -f enough-signed.tx

## Show that a delegated LogicSig signed by the PQ account can authorize a txn
algokey salted sign-program -k pq.sk -p pq-true.tok -o pq-true.lsig
${gcmd} clerk send -a 7777 -f "${PQADDRESS}" -t "${ACCOUNT}" --fee 3000 -L pq-true.lsig

BALANCE=$(${gcmd} account balance -a "${PQADDRESS}" | awk '{ print $1 }')
EXPECT=$((FUNDING - 6666 - 3000 - 7777 - 3000))
if [ "$BALANCE" -ne "$EXPECT" ]; then
    date "+${scriptname} FAIL wanted balance=${EXPECT} but got ${BALANCE} %Y%m%d_%H%M%S"
    false
fi

# Repeat with falcon-512, generated with an explicit scheme. Its fee surcharge
# is half of falcon-1024's, so the required min fee is 2mA instead of 3mA.
algokey salted generate -S falcon-512 -k pq512.sk > generate512.out

grep 'Scheme: falcon-512' < generate512.out
PQ512MNEMONIC=$(grep 'Private key mnemonic:' < generate512.out | sed 's/Private key mnemonic: //')
PQ512ADDRESS=$(grep 'Address:' < generate512.out | sed 's/Address: //')

echo "$PQ512MNEMONIC"
echo "$PQ512ADDRESS"

# Restoring from mnemonic reproduces the key file.
algokey salted import -m "$PQ512MNEMONIC" -S falcon-512 -k pq512-restored.sk
cmp pq512.sk pq512-restored.sk

# Fund pq-512 account below one reward unit to avoid unexpected balance drift from rewards.
${gcmd} clerk send -a "${FUNDING}" -f "${ACCOUNT}" -t "${PQ512ADDRESS}"

## Show the usual min fee is insufficient
${gcmd} clerk send -a 5555 -f "${PQ512ADDRESS}" -t "${ACCOUNT}" --fee 1000 -o low512.tx
algokey salted sign -t low512.tx -k pq512.sk -o low512-signed.tx
set +o pipefail
${gcmd} clerk rawsend -f low512-signed.tx 2>&1 | grep "1mA fees is less than 2mA" || exit 1
set -o pipefail

## Show that 2000 min fee is sufficient
${gcmd} clerk send -a 6666 -f "${PQ512ADDRESS}" -t "${ACCOUNT}" --fee 2000 -o enough512.tx
algokey salted sign -t enough512.tx -k pq512.sk -o enough512-signed.tx
${gcmd} clerk rawsend -f enough512-signed.tx

## Show that a delegated LogicSig signed by the PQ-512 account can authorize a txn
algokey salted sign-program -k pq512.sk -p pq-true.tok -o pq-true512.lsig
${gcmd} clerk send -a 7777 -f "${PQ512ADDRESS}" -t "${ACCOUNT}" --fee 2000 -L pq-true512.lsig

BALANCE512=$(${gcmd} account balance -a "${PQ512ADDRESS}" | awk '{ print $1 }')
EXPECT512=$((FUNDING - 6666 - 2000 - 7777 - 2000))
if [ "$BALANCE512" -ne "$EXPECT512" ]; then
    date "+${scriptname} FAIL wanted falcon-512 balance=${EXPECT512} but got ${BALANCE512} %Y%m%d_%H%M%S"
    false
fi

# Repeat with Ed25519 hashed account, generated with an explicit scheme. Ed25519 has no fee surcharge.
algokey salted generate -S ed25519 -k pq-ed.sk > generate-ed.out

grep 'Scheme: ed25519' < generate-ed.out
EDMNEMONIC=$(grep 'Private key mnemonic:' < generate-ed.out | sed 's/Private key mnemonic: //')
EDADDRESS=$(grep 'Address:' < generate-ed.out | sed 's/Address: //')

echo "$EDMNEMONIC"
echo "$EDADDRESS"

algokey salted import -m "$EDMNEMONIC" -S ed25519 -k pq-ed-restored.sk
cmp pq-ed.sk pq-ed-restored.sk
algokey salted check-address "$EDADDRESS"

${gcmd} clerk send -a "${FUNDING}" -f "${ACCOUNT}" -t "${EDADDRESS}"

# The usual minimum fee is sufficient.
${gcmd} clerk send -a 6666 -f "${EDADDRESS}" -t "${ACCOUNT}" --fee 1000 -o ed.tx
algokey salted sign -t ed.tx -k pq-ed.sk -o ed-signed.tx
${gcmd} clerk rawsend -f ed-signed.tx

algokey salted sign-program -k pq-ed.sk -p pq-true.tok -o pq-ed-true.lsig
${gcmd} clerk send -a 7777 -f "${EDADDRESS}" -t "${ACCOUNT}" --fee 1000 -L pq-ed-true.lsig

BALANCEED=$(${gcmd} account balance -a "${EDADDRESS}" | awk '{ print $1 }')
EXPECTED=$((FUNDING - 6666 - 1000 - 7777 - 1000))
if [ "$BALANCEED" -ne "$EXPECTED" ]; then
    date "+${scriptname} FAIL wanted ed25519 balance=${EXPECTED} but got ${BALANCEED} %Y%m%d_%H%M%S"
    false
fi

# Repeat with each ML-DSA parameter set. Their fee surcharges are 0.6, 0.9
# and 1.3 min fees, so the required fees are 1.6mA, 1.9mA and 2.3mA.
for SCHEME_FEE in ml-dsa-44:1600:1.600mA ml-dsa-65:1900:1.900mA ml-dsa-87:2300:2.300mA; do
    IFS=: read -r SCHEME FEE FEESTR <<< "${SCHEME_FEE}"

    algokey salted generate -S "${SCHEME}" -k "${SCHEME}.sk" > "generate-${SCHEME}.out"

    grep "Scheme: ${SCHEME}" < "generate-${SCHEME}.out"
    MLMNEMONIC=$(grep 'Private key mnemonic:' < "generate-${SCHEME}.out" | sed 's/Private key mnemonic: //')
    MLADDRESS=$(grep 'Address:' < "generate-${SCHEME}.out" | sed 's/Address: //')

    echo "$MLMNEMONIC"
    echo "$MLADDRESS"

    # Restoring from mnemonic reproduces the key file.
    algokey salted import -m "$MLMNEMONIC" -S "${SCHEME}" -k "${SCHEME}-restored.sk"
    cmp "${SCHEME}.sk" "${SCHEME}-restored.sk"

    ${gcmd} clerk send -a "${FUNDING}" -f "${ACCOUNT}" -t "${MLADDRESS}"

    ## Show the usual min fee is insufficient
    ${gcmd} clerk send -a 5555 -f "${MLADDRESS}" -t "${ACCOUNT}" --fee 1000 -o "low-${SCHEME}.tx"
    algokey salted sign -t "low-${SCHEME}.tx" -k "${SCHEME}.sk" -o "low-${SCHEME}-signed.tx"
    set +o pipefail
    ${gcmd} clerk rawsend -f "low-${SCHEME}-signed.tx" 2>&1 | grep "1mA fees is less than ${FEESTR}" || exit 1
    set -o pipefail

    ## Signing is hedged, so signing the same transaction twice gives different
    ## bytes. Once one copy is committed, the other is a duplicate.
    ${gcmd} clerk send -a 6666 -f "${MLADDRESS}" -t "${ACCOUNT}" --fee "${FEE}" -o "enough-${SCHEME}.tx"
    algokey salted sign -t "enough-${SCHEME}.tx" -k "${SCHEME}.sk" -o "enough-${SCHEME}-signed.tx"
    algokey salted sign -t "enough-${SCHEME}.tx" -k "${SCHEME}.sk" -o "enough-${SCHEME}-resigned.tx"
    if cmp -s "enough-${SCHEME}-signed.tx" "enough-${SCHEME}-resigned.tx"; then
        date "+${scriptname} FAIL ${SCHEME} signed the same transaction twice with the same bytes %Y%m%d_%H%M%S"
        false
    fi
    ${gcmd} clerk rawsend -f "enough-${SCHEME}-signed.tx"
    set +o pipefail
    ${gcmd} clerk rawsend -f "enough-${SCHEME}-resigned.tx" 2>&1 | grep "transaction already in ledger" || exit 1
    set -o pipefail

    ## Show that a delegated LogicSig signed by the ML-DSA account can authorize a txn
    algokey salted sign-program -k "${SCHEME}.sk" -p pq-true.tok -o "pq-true-${SCHEME}.lsig"
    ${gcmd} clerk send -a 7777 -f "${MLADDRESS}" -t "${ACCOUNT}" --fee "${FEE}" -L "pq-true-${SCHEME}.lsig"

    BALANCEML=$(${gcmd} account balance -a "${MLADDRESS}" | awk '{ print $1 }')
    EXPECTML=$((FUNDING - 6666 - FEE - 7777 - FEE))
    if [ "$BALANCEML" -ne "$EXPECTML" ]; then
        date "+${scriptname} FAIL wanted ${SCHEME} balance=${EXPECTML} but got ${BALANCEML} %Y%m%d_%H%M%S"
        false
    fi
done
