#!/bin/bash

date '+rawsend-test start %Y%m%d_%H%M%S'

set -e
set -x
set -o pipefail
export SHELLOPTS

WALLET=$1

gcmd="goal -w ${WALLET}"

ACCOUNTA=$(${gcmd} account list|awk '{ print $3 }')
ACCOUNTB=$(${gcmd} account new|awk '{ print $6 }')

# prepare the signed txn for rawsend
${gcmd} clerk send -a 100000000 -f ${ACCOUNTA} -t ${ACCOUNTB} -o ${TEMPDIR}/send-from-a-to-b.txn
${gcmd} clerk sign -i ${TEMPDIR}/send-from-a-to-b.txn -o ${TEMPDIR}/send-from-a-to-b.stxn

# rawsend should go through
RES=$(${gcmd} clerk rawsend -f ${TEMPDIR}/send-from-a-to-b.stxn 2>&1 || true)
EXPERROR='rejected'
if [[ $RES == *"${EXPERROR}"* ]]; then
    date '+rawsend-test sending raw signed payment txn should not be rejected %Y%m%d_%H%M%S'
    false
fi

# pending round info matching from log, should always be ascending order
STILL_PENDING_PATTERN='still pending as of round [[:digit:]]+'

PENDING_ROUNDS=$(echo ${RES} | grep -Eo "${STILL_PENDING_PATTERN}" | grep -Eo '[[:digit:]]+')

echo "$PENDING_ROUNDS" | sort -nuC
SORT_CHECK=$?

if [[ ${SORT_CHECK} -ne 0 ]]; then
    date '+rawsend-test pending rounds should be in ascending order %Y%m%d_%H%M%S'
    false
fi

LAST_PENDING_ROUND=$(echo "$PENDING_ROUNDS" | tail -1)

# prepare commmited round, and committed round should always > any of the pending rounds
COMMITTED_PATTERN='committed in round [[:digit:]]+'
COMMITTED_ROUND=$(echo ${RES} | grep -Eo "${COMMITTED_PATTERN}" | grep -Eo '[[:digit:]]+')

if [[ ! ${COMMITTED_ROUND} -gt ${LAST_PENDING_ROUND} ]]; then
    date '+rawsend-test pending rounds should always be smaller than committed round %Y%m%d_%H%M%S'
    false
fi
