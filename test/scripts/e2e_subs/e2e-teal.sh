#!/bin/bash

date '+e2e_teal start %Y%m%d_%H%M%S'

set -e
set -x
set -o pipefail
export SHELLOPTS

WALLET=$1

gcmd="goal -w ${WALLET}"

ACCOUNT=$(${gcmd} account list|awk '{ print $3 }')

# prints:
# Created new account with address UCTHHNBEAUWHDQWQI5DGQCTB7AR4CSVNU5YNPROAYQIT3Y3LKVDFAA5M6Q
ACCOUNTB=$(${gcmd} account new|awk '{ print $6 }')

ROUND=$(goal node status | grep 'Last committed block:'|awk '{ print $4 }')
TIMEOUT_ROUND=$((${ROUND} + 14))

# timeout after 14 rounds
python ${GOPATH}/src/github.com/algorand/go-algorand/data/transactions/logic/tlhc.py --from ${ACCOUNT} --to ${ACCOUNTB} --timeout-round ${TIMEOUT_ROUND} > ${TEMPDIR}/tlhc.teal 2> ${TEMPDIR}/tlhc.teal.secret

cat ${TEMPDIR}/tlhc.teal

ACCOUNT_TLHC=$(${gcmd} clerk compile -n ${TEMPDIR}/tlhc.teal|awk '{ print $2 }')

${gcmd} clerk send --amount 1000000 --from ${ACCOUNT} --to ${ACCOUNT_TLHC}

set +e

# this will be rejected until after the round is late
${gcmd} clerk send --from-program ${TEMPDIR}/tlhc.teal --to ${ACCOUNT} --close-to ${ACCOUNT} --amount 1 --argb64 AA==
if [ $? -eq 0 ]; then
    echo "early refund should have failed"
    exit 1
fi

TLHC_SECRET=$(awk '{ print $4 }'<${TEMPDIR}/tlhc.teal.secret)

# this will be rejected until after the timeout round
${gcmd} clerk send --from-program ${TEMPDIR}/tlhc.teal --to ${ACCOUNT} --close-to ${ACCOUNT} --amount 1 --argb64 ${TLHC_SECRET}
if [ $? -eq 0 ]; then
    echo "early refund with secret should have failed"
    exit 1
fi

set -e
# this should pass
${gcmd} clerk send --from-program ${TEMPDIR}/tlhc.teal --to ${ACCOUNTB} --close-to ${ACCOUNTB} --amount 1 --argb64 ${TLHC_SECRET}
set +e

# but it should fail the second time because the money was spent
${gcmd} clerk send --from-program ${TEMPDIR}/tlhc.teal --to ${ACCOUNTB} --close-to ${ACCOUNTB} --amount 1 --argb64 ${TLHC_SECRET}
if [ $? -eq 0 ]; then
    echo "empty spend should have failed"
    exit 1
fi

set -e
${gcmd} clerk send --amount 1000000 --from ${ACCOUNT} --to ${ACCOUNT_TLHC}

# timeout round should pass. some of the 35 seconds was eaten by prior ops.
CROUND=$(goal node status | grep 'Last committed block:'|awk '{ print $4 }')
while [ $CROUND -lt $TIMEOUT_ROUND ]; do
    goal node wait --waittime 30
    CROUND=$(goal node status | grep 'Last committed block:'|awk '{ print $4 }')
done

${gcmd} clerk send --from-program ${TEMPDIR}/tlhc.teal --to ${ACCOUNT} --close-to ${ACCOUNT} --amount 1 --argb64 AA==

cat >${TEMPDIR}/true.teal<<EOF
#pragma version 2
int 1
EOF

${gcmd} clerk compile -o ${TEMPDIR}/true.lsig -s -a ${ACCOUNT} ${TEMPDIR}/true.teal

${gcmd} clerk send -f ${ACCOUNT} -t ${ACCOUNTB} -a 1000000 -L ${TEMPDIR}/true.lsig

${gcmd} clerk send -f ${ACCOUNT} -t ${ACCOUNTB} -a 1000000 -o ${TEMPDIR}/one.tx

${gcmd} clerk sign -L ${TEMPDIR}/true.lsig -i ${TEMPDIR}/one.tx -o ${TEMPDIR}/one.stx

${gcmd} clerk rawsend -f ${TEMPDIR}/one.stx

${gcmd} clerk dryrun -t ${TEMPDIR}/one.stx

ACCOUNT_TRUE=$(${gcmd} clerk compile -n ${TEMPDIR}/true.teal|awk '{ print $2 }')

${gcmd} clerk send --amount 1000000 --from ${ACCOUNT} --to ${ACCOUNT_TRUE}

${gcmd} clerk send --amount 10 --from-program ${TEMPDIR}/true.teal --to ${ACCOUNTB}

${gcmd} clerk send --amount 10 --from ${ACCOUNT_TRUE} --to ${ACCOUNTB} -o ${TEMPDIR}/true.tx

${gcmd} clerk sign -i ${TEMPDIR}/true.tx -o ${TEMPDIR}/true.stx --program ${TEMPDIR}/true.teal

${gcmd} clerk rawsend -f ${TEMPDIR}/true.stx

${gcmd} clerk inspect ${TEMPDIR}/true.stx

${gcmd} clerk compile -D ${TEMPDIR}/true.lsig

ACCOUNTC=$(${gcmd} account new|awk '{ print $6 }')

ACCOUNTM=$(${gcmd} account multisig new -T 2 ${ACCOUNT} ${ACCOUNTB} ${ACCOUNTC}|awk '{ print $6 }')


${gcmd} clerk multisig signprogram -p ${TEMPDIR}/true.teal -a ${ACCOUNT} -A ${ACCOUNTM} -o ${TEMPDIR}/mtrue.lsig

${gcmd} clerk multisig signprogram -L ${TEMPDIR}/mtrue.lsig -a ${ACCOUNTC}

${gcmd} clerk send --amount 1000000 --from ${ACCOUNT} --to ${ACCOUNTM}

${gcmd} clerk send --amount 200000 --from ${ACCOUNTM} --to ${ACCOUNTC} -L ${TEMPDIR}/mtrue.lsig

echo "#pragma version 1" | ${gcmd} clerk compile -
echo "#pragma version 2" | ${gcmd} clerk compile -

set +o pipefail
# The compile will fail, but this tests against a regression in which compile SEGV'd
echo "#pragma version 100" | ${gcmd} clerk compile - 2>&1 | grep "unsupported version"
set -o pipefail


date '+e2e_teal OK %Y%m%d_%H%M%S'
