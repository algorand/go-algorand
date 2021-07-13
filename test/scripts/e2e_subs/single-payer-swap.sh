#!/bin/bash

filename=$(basename "$0")
scriptname="${filename%.*}"
date "+${scriptname} start %Y%m%d_%H%M%S"

set -e
set -x
set -o pipefail
export SHELLOPTS

WALLET=$1

gcmd="goal -w ${WALLET}"

PAYER=$(${gcmd} account list|awk '{ print $3 }')
MOOCHER=$(${gcmd} account new|awk '{ print $6 }')

# Fund MOOCHER, 1M
${gcmd} clerk send -a 1000000 -f "${PAYER}" -t "${MOOCHER}"

# Payer and Moocher are going to pay each other 100 mAlgos, but
# Moocher is not going to pay the minfee (Payer will pay double)

# Fair number of temporary files, just cd into TEMPDIR first
cd ${TEMPDIR}

# Check a low fee from moocher
${gcmd} clerk send -a 100 -f "${MOOCHER}" -t "${PAYER}" --fee 2 -o cheap.txn
# Since goal was modified to allow < minfee when this feature was added, let's confirm
msgpacktool -d < cheap.txn | grep fee | grep 2
${gcmd} clerk send -a 100 -f "${PAYER}" -t "${MOOCHER}" --fee 2000 -o expensive.txn
cat cheap.txn expensive.txn > both.txn
${gcmd} clerk group -i both.txn -o group.txn
${gcmd} clerk sign -i group.txn -o group.stx
${gcmd} clerk rawsend -f group.stx

# Check a zero fee from moocher
${gcmd} clerk send -a 100 -f "${MOOCHER}" -t "${PAYER}" --fee 0 -o cheap.txn
# Since goal was modified to allow zero when this feature was added, let's confirm
# that it's not encoded (should be "omitempty")
set +e
FOUND=$(msgpacktool -d < cheap.txn | grep fee)
set -e
if [[ $FOUND != "" ]]; then
    date "+{scriptname} FAIL fee was improperly encoded $FOUND %Y%m%d_%H%M%S"
    false
fi

${gcmd} clerk send -a 100 -f "${PAYER}" -t "${MOOCHER}" --fee 2000 -o expensive.txn
cat cheap.txn expensive.txn > both.txn
${gcmd} clerk group -i both.txn -o group.txn
${gcmd} clerk sign -i group.txn -o group.stx
${gcmd} clerk rawsend -f group.stx


date "+${scriptname} OK %Y%m%d_%H%M%S"
