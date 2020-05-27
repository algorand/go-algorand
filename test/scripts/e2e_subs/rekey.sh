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
