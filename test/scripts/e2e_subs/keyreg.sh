#!/bin/bash

date '+e2e_subs/keyreg.sh start %Y%m%d_%H%M%S'

my_dir="$(dirname "$0")"
source "$my_dir/rest.sh" "$@"

set -exo pipefail
export SHELLOPTS

WALLET=$1

gcmd="goal -w ${WALLET}"

# Get network's minimum fee
MIN_FEE=$(get_min_fee)
echo "Network MinFee: $MIN_FEE"

ACCOUNT=$(${gcmd} account list|awk '{ print $3 }')

# secret algokey override
ALGOKEY_GENESIS_HASH=$(goal node status | grep 'Genesis hash:'|awk '{ print $3 }')
export ALGOKEY_GENESIS_HASH
# Test key registration
KEYS="${TEMPDIR}/foo.keys"
TXN="${TEMPDIR}/keyreg.txn"
STXN="${TEMPDIR}/keyreg.stxn"
algokey part generate --first 1 --last 1000 --parent "${ACCOUNT}" --keyfile "${KEYS}"
algokey part keyreg --network placeholder --keyfile "${KEYS}" --firstvalid 1 --fee "${MIN_FEE}" --outputFile "${TXN}"
# technically algokey could be used to sign at this point, that would require
# exporting secrets from the wallet.
${gcmd} clerk sign -i "${TXN}" -o "${STXN}"
${gcmd} clerk rawsend -f "${STXN}"

TXN2="${TEMPDIR}/keydereg.txn"
STXN2="${TEMPDIR}/keydereg.stxn"
# Test key de-registration
algokey part keyreg --network placeholder --offline --account "${ACCOUNT}" --firstvalid 1 --fee "${MIN_FEE}" --outputFile "${TXN2}"
${gcmd} clerk sign -i "${TXN2}" -o "${STXN2}"
${gcmd} clerk rawsend -f "${STXN2}"
