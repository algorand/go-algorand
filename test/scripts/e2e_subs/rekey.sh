#!/bin/bash

date '+e2e_subs/rekey.sh start %Y%m%d_%H%M%S'

set -exo pipefail
export SHELLOPTS

WALLET=$1

gcmd="goal -w ${WALLET}"

ACCOUNT=$(${gcmd} account list|awk '{ print $3 }')
ACCOUNTB=$(${gcmd} account new|awk '{ print $6 }')

algokey generate > "${TEMPDIR}/rekey"
mnemonic=$(grep 'Private key mnemonic:' < "${TEMPDIR}/rekey" | sed 's/Private key mnemonic: //')
ACCOUNTC=$(grep 'Public key:' < "${TEMPDIR}/rekey" | sed 's/Public key: //')
${gcmd} account import -m "${mnemonic}"

${gcmd} clerk send -a 10000000 -f "${ACCOUNT}" -t "${ACCOUNTB}" --rekey-to "${ACCOUNTC}"

${gcmd} clerk send -a 13000000 -f "${ACCOUNT}" -t "${ACCOUNTB}" -o "${TEMPDIR}/ntxn"
${gcmd} clerk sign -S "${ACCOUNTC}" -i "${TEMPDIR}/ntxn" -o "${TEMPDIR}/nstxn"
${gcmd} clerk rawsend -f "${TEMPDIR}/nstxn"

BALANCEB=$(${gcmd} account balance -a "${ACCOUNTB}" | awk '{ print $1 }')
if [ "$BALANCEB" -ne 23000000 ]; then
    date "+e2e_subs/rekey.sh FAIL wanted balance=23000000 but got ${BALANCEB} %Y%m%d_%H%M%S"
    false
fi

# Rekey from A to C back to A [A -> C -> A].
${gcmd} clerk send -a 10000 -f "${ACCOUNT}" -t "${ACCOUNTB}" --rekey-to "${ACCOUNT}" -s -o "${TEMPDIR}/ntxn2"
${gcmd} clerk sign -S "${ACCOUNTC}" -i "${TEMPDIR}/ntxn2" -o "${TEMPDIR}/nstxn2"
${gcmd} clerk rawsend -f "${TEMPDIR}/nstxn2"

BALANCEB=$(${gcmd} account balance -a "${ACCOUNTB}" | awk '{ print $1 }')
if [ "$BALANCEB" -ne 33000000 ]; then
    date "+e2e_subs/rekey.sh FAIL wanted balance=23000000 but got ${BALANCEB} %Y%m%d_%H%M%S"
    false
fi

# Rekey from A to B to D [A -> B -> D].
ACCOUNTD=$(${gcmd} account new|awk '{ print $6 }')
ACCOUNTE=$(${gcmd} account new|awk '{ print $6 }')

${gcmd} clerk send -a 10000000 -f "${ACCOUNT}" -t "${ACCOUNTE}" --rekey-to "${ACCOUNTB}"
${gcmd} clerk send -a 10000000 -f "${ACCOUNT}" -t "${ACCOUNTE}" -o "${TEMPDIR}/ntxn3"
${gcmd} clerk sign -S "${ACCOUNTB}" -i "${TEMPDIR}/ntxn3" -o "${TEMPDIR}/nstxn3"
${gcmd} clerk rawsend -f "${TEMPDIR}/nstxn3"

BALANCEE=$(${gcmd} account balance -a "${ACCOUNTE}" | awk '{ print $1 }')
if [ "$BALANCEE" -ne 20000000 ]; then
    date "+e2e_subs/rekey.sh FAIL wanted balance=23000000 but got ${BALANCEE} %Y%m%d_%H%M%S"
    false
fi
echo "$BALANCEE"

${gcmd} clerk send -a 10000000 -f "${ACCOUNT}" -t "${ACCOUNTE}" --rekey-to "${ACCOUNTD}" -s -o "${TEMPDIR}/ntxn4"
${gcmd} clerk sign -S "${ACCOUNTB}" -i "${TEMPDIR}/ntxn4" -o "${TEMPDIR}/nstxn4"
${gcmd} clerk rawsend -f "${TEMPDIR}/nstxn4"

BALANCEE=$(${gcmd} account balance -a "${ACCOUNTE}" | awk '{ print $1 }')
if [ "$BALANCEE" -ne 30000000 ]; then
    date "+e2e_subs/rekey.sh FAIL wanted balance=30000000 but got ${BALANCEE} %Y%m%d_%H%M%S"
    false
fi

date '+e2e_subs/rekey.sh OK %Y%m%d_%H%M%S'

