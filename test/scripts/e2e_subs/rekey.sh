#!/bin/bash

date '+e2e_subs/rekey.sh start %Y%m%d_%H%M%S'

set -e
set -x
set -o pipefail
export SHELLOPTS

WALLET=$1

gcmd="goal -w ${WALLET}"

ACCOUNT=$(${gcmd} account list|awk '{ print $3 }')
ACCOUNTB=$(${gcmd} account new|awk '{ print $6 }')

# Rekeying should fail if in a txn group with a < v2 TEAL program

# Make v1 program
echo -e 'int 1' > "${TEMPDIR}/simplev1.teal"
ESCROWV1=$(${gcmd} clerk compile ${TEMPDIR}/simplev1.teal -o ${TEMPDIR}/simplev1.tealc | awk '{ print $2 }')

# Make a > v1 program
echo -e '#pragma version 2\nint 1' > "${TEMPDIR}/simple.teal"
ESCROWV2=$(${gcmd} clerk compile ${TEMPDIR}/simple.teal -o ${TEMPDIR}/simple.tealc | awk '{ print $2 }')

# Fund v1 escrow, v2 escrow, and ACCOUNTD
ACCOUNTD=$(${gcmd} account new|awk '{ print $6 }')
${gcmd} clerk send -a 10000000 -f ${ACCOUNT} -t ${ESCROWV1}
${gcmd} clerk send -a 10000000 -f ${ACCOUNT} -t ${ESCROWV2}
${gcmd} clerk send -a 10000000 -f ${ACCOUNT} -t ${ACCOUNTD}

# Plan: make a txn group. First one is rekey-to payment from $ACCOUNTD, second
# one is regular payment from v1 escrow. (Should fail when we send it).

${gcmd} clerk send -a 1 -f ${ACCOUNTD} -t ${ACCOUNTD} --rekey-to ${ACCOUNT} -o ${TEMPDIR}/txn0.tx
${gcmd} clerk send -a 1 --from-program "${TEMPDIR}/simplev1.teal" -t ${ACCOUNTD} -o ${TEMPDIR}/txn1.tx
cat ${TEMPDIR}/txn0.tx ${TEMPDIR}/txn1.tx > ${TEMPDIR}/group0.tx

# Build + sign group
${gcmd} clerk group -i ${TEMPDIR}/group0.tx -o ${TEMPDIR}/group0_grouped.tx
${gcmd} clerk split -i ${TEMPDIR}/group0_grouped.tx -o ${TEMPDIR}/group0_split.txn
${gcmd} clerk sign -i ${TEMPDIR}/group0_split-0.txn -o ${TEMPDIR}/group0_split-0.stxn
cat ${TEMPDIR}/group0_split-0.stxn ${TEMPDIR}/group0_split-1.txn > ${TEMPDIR}/group0_signed.stxn

# Broadcast group (should fail)
RES=$(${gcmd} clerk rawsend -f ${TEMPDIR}/group0_signed.stxn 2>&1 || true)
EXPERROR='program version must be >= 2 for this transaction group'
if [[ $RES != *"${EXPERROR}"* ]]; then
    date '+e2e_subs/rekey.sh FAIL txn group with rekey transaction should require teal version >= 2 %Y%m%d_%H%M%S'
    false
fi

# Plan: make a txn group. First one is rekey-to payment from $ACCOUNTD, second
# one is regular payment from v1 escrow. (Should succeed when we send it).

${gcmd} clerk send -a 1 -f ${ACCOUNTD} -t ${ACCOUNTD} --rekey-to ${ACCOUNT} -o ${TEMPDIR}/txn2.tx
${gcmd} clerk send -a 1 --from-program "${TEMPDIR}/simple.teal" -t ${ACCOUNTD} -o ${TEMPDIR}/txn3.tx
cat ${TEMPDIR}/txn2.tx ${TEMPDIR}/txn3.tx > ${TEMPDIR}/group1.tx

# Build + sign group
${gcmd} clerk group -i ${TEMPDIR}/group1.tx -o ${TEMPDIR}/group1_grouped.tx
${gcmd} clerk split -i ${TEMPDIR}/group1_grouped.tx -o ${TEMPDIR}/group1_split.txn
${gcmd} clerk sign -i ${TEMPDIR}/group1_split-0.txn -o ${TEMPDIR}/group1_split-0.stxn
cat ${TEMPDIR}/group1_split-0.stxn ${TEMPDIR}/group1_split-1.txn > ${TEMPDIR}/group1_signed.stxn

# Broadcast group (should succeed)
${gcmd} clerk rawsend -f ${TEMPDIR}/group1_signed.stxn

# Regular rekeying test
algokey generate > ${TEMPDIR}/rekey
mnemonic=$(grep 'Private key mnemonic:' < ${TEMPDIR}/rekey | sed 's/Private key mnemonic: //')
ACCOUNTC=$(grep 'Public key:' < ${TEMPDIR}/rekey | sed 's/Public key: //')
${gcmd} account import -m "${mnemonic}"

${gcmd} clerk send -a 10000000 -f ${ACCOUNT} -t ${ACCOUNTB} --rekey-to ${ACCOUNTC}

${gcmd} clerk send -a 13000000 -f ${ACCOUNT} -t ${ACCOUNTB} -o ${TEMPDIR}/ntxn
${gcmd} clerk sign -S ${ACCOUNTC} -i ${TEMPDIR}/ntxn -o ${TEMPDIR}/nstxn
${gcmd} clerk rawsend -f ${TEMPDIR}/nstxn

BALANCEB=$(${gcmd} account balance -a ${ACCOUNTB} | awk '{ print $1 }')
if [ $BALANCEB -ne 23000000 ]; then
    date '+e2e_subs/rekey.sh FAIL wanted balance=23000000 but got ${BALANCEB} %Y%m%d_%H%M%S'
    false
fi

date '+e2e_subs/rekey.sh OK %Y%m%d_%H%M%S'
