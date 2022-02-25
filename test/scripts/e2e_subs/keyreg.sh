#!/bin/bash

date '+e2e_subs/keyreg.sh start %Y%m%d_%H%M%S'

set -exo pipefail
export SHELLOPTS

WALLET=$1

gcmd="goal -w ${WALLET}"

ACCOUNT=$(${gcmd} account list|awk '{ print $3 }')
ACCOUNTB=$(${gcmd} account new|awk '{ print $6 }')

# secret algokey override
export ALGOKEY_GENESIS_ID=$(goal node status | grep 'Genesis ID:'|awk '{ print $3 }')
export ALGOKEY_GENESIS_HASH=$(goal node status | grep 'Genesis hash:'|awk '{ print $3 }')

# Test key registration
KEYS="${TEMPDIR}/foo.keys"
TXN="${TEMPDIR}/keyreg.txn"
STXN="${TEMPDIR}/keyreg.stxn"
algokey part generate --first 1 --last 1000 --parent ${ACCOUNT} --keyfile "${KEYS}"
algokey part keyreg --network placeholder --partkey-file "${KEYS}" --first-valid 1 --tx-file "${TXN}"
# technically algokey could be used to sign at this point, that would require
# exporting secrets from the wallet.
${gcmd} clerk sign -i "${TXN}" -o "${STXN}"
${gcmd} clerk rawsend -f "${STXN}"

TXN2="${TEMPDIR}/keydereg.txn"
STXN2="${TEMPDIR}/keydereg.stxn"
# Test key de-registration
algokey part keyreg --network placeholder --offline --account "${ACCOUNT}" --first-valid 1 --tx-file "${TXN2}"
${gcmd} clerk sign -i "${TXN2}" -o "${STXN2}"
${gcmd} clerk rawsend -f "${STXN2}"
