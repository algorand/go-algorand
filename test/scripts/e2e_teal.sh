#!/bin/bash

date '+e2e_teal start %Y%m%d_%H%M%S'

set -e
set -x
export GOPATH=$(go env GOPATH)

TEMPDIR=$(mktemp -d)
trap "rm -rf $TEMPDIR" 0

NETDIR=${TEMPDIR}/net

export PATH=${BINDIR}:${PATH}

${BINDIR}/goal network create -r ${NETDIR} -n tbd -t ${GOPATH}/src/github.com/algorand/go-algorand/test/testdata/nettemplates/TwoNodes50EachFuture.json

${BINDIR}/goal network start -r ${NETDIR}

# replaces prior trap0
trap "${BINDIR}/goal network stop -r ${NETDIR}; rm -rf ${TEMPDIR}" 0

export ALGORAND_DATA=${NETDIR}/Node

ACCOUNT=$(${BINDIR}/goal account list|awk '{ print $3 }')

# prints:
# Created new account with address UCTHHNBEAUWHDQWQI5DGQCTB7AR4CSVNU5YNPROAYQIT3Y3LKVDFAA5M6Q
ACCOUNTB=$(${BINDIR}/goal account new|awk '{ print $6 }')

ROUND=$(${BINDIR}/goal node status | grep 'Last committed block:'|awk '{ print $4 }')
TIMEOUT_ROUND=$((${ROUND} + 7))

# timeout after 7 rounds
python ${GOPATH}/src/github.com/algorand/go-algorand/data/transactions/logic/tlhc.py --from ${ACCOUNT} --to ${ACCOUNTB} --timeout-round ${TIMEOUT_ROUND} > ${TEMPDIR}/tlhc.teal 2> ${TEMPDIR}/tlhc.teal.secret

cat ${TEMPDIR}/tlhc.teal

ACCOUNT_TLHC=$(${BINDIR}/goal clerk compile -n ${TEMPDIR}/tlhc.teal|awk '{ print $2 }')

${BINDIR}/goal clerk send --amount 1000000 --from ${ACCOUNT} --to ${ACCOUNT_TLHC}

set +e

# this will be rejected until after the round is late
${BINDIR}/goal clerk send --from-program ${TEMPDIR}/tlhc.teal --to ${ACCOUNT} --close-to ${ACCOUNT} --amount 1 --argb64 AA==
if [ $? -eq 0 ]; then
    echo "early refund should have failed"
    exit 1
fi

TLHC_SECRET=$(awk '{ print $4 }'<${TEMPDIR}/tlhc.teal.secret)

# this will be rejected until after the timeout round
${BINDIR}/goal clerk send --from-program ${TEMPDIR}/tlhc.teal --to ${ACCOUNT} --close-to ${ACCOUNT} --amount 1 --argb64 ${TLHC_SECRET}
if [ $? -eq 0 ]; then
    echo "early refund with secret should have failed"
    exit 1
fi

set -e
# this should pass
${BINDIR}/goal clerk send --from-program ${TEMPDIR}/tlhc.teal --to ${ACCOUNTB} --close-to ${ACCOUNTB} --amount 1 --argb64 ${TLHC_SECRET}
set +e

# but it should fail the second time because the money was spent
${BINDIR}/goal clerk send --from-program ${TEMPDIR}/tlhc.teal --to ${ACCOUNTB} --close-to ${ACCOUNTB} --amount 1 --argb64 ${TLHC_SECRET}
if [ $? -eq 0 ]; then
    echo "empty spend should have failed"
    exit 1
fi

set -e
${BINDIR}/goal clerk send --amount 1000000 --from ${ACCOUNT} --to ${ACCOUNT_TLHC}

# timeout round should pass. some of the 35 seconds was eaten by prior ops.
CROUND=$(${BINDIR}/goal node status | grep 'Last committed block:'|awk '{ print $4 }')
while [ $CROUND -lt $TIMEOUT_ROUND ]; do
    ${BINDIR}/goal node wait
    CROUND=$(${BINDIR}/goal node status | grep 'Last committed block:'|awk '{ print $4 }')
done

${BINDIR}/goal clerk send --from-program ${TEMPDIR}/tlhc.teal --to ${ACCOUNT} --close-to ${ACCOUNT} --amount 1 --argb64 AA==

cat >${TEMPDIR}/true.teal<<EOF
int 1
EOF

${BINDIR}/goal clerk compile -o ${TEMPDIR}/true.lsig -s -a ${ACCOUNT} ${TEMPDIR}/true.teal

${BINDIR}/goal clerk send -f ${ACCOUNT} -t ${ACCOUNTB} -a 1000000 -L ${TEMPDIR}/true.lsig

${BINDIR}/goal clerk send -f ${ACCOUNT} -t ${ACCOUNTB} -a 1000000 -o ${TEMPDIR}/one.tx

${BINDIR}/goal clerk sign -L ${TEMPDIR}/true.lsig -i ${TEMPDIR}/one.tx -o ${TEMPDIR}/one.stx

${BINDIR}/goal clerk rawsend -f ${TEMPDIR}/one.stx

${BINDIR}/goal clerk dryrun -t ${TEMPDIR}/one.stx

ACCOUNT_TRUE=$(${BINDIR}/goal clerk compile -n ${TEMPDIR}/true.teal|awk '{ print $2 }')

${BINDIR}/goal clerk send --amount 1000000 --from ${ACCOUNT} --to ${ACCOUNT_TRUE}

${BINDIR}/goal clerk send --amount 10 --from-program ${TEMPDIR}/true.teal --to ${ACCOUNTB}

${BINDIR}/goal clerk send --amount 10 --from ${ACCOUNT_TRUE} --to ${ACCOUNTB} -o ${TEMPDIR}/true.tx

${BINDIR}/goal clerk sign -i ${TEMPDIR}/true.tx -o ${TEMPDIR}/true.stx --program ${TEMPDIR}/true.teal

${BINDIR}/goal clerk rawsend -f ${TEMPDIR}/true.stx

${BINDIR}/goal clerk inspect ${TEMPDIR}/true.stx

${BINDIR}/goal clerk compile -D ${TEMPDIR}/true.lsig

ACCOUNTC=$(${BINDIR}/goal account new|awk '{ print $6 }')

ACCOUNTM=$(${BINDIR}/goal account multisig new -T 2 ${ACCOUNT} ${ACCOUNTB} ${ACCOUNTC}|awk '{ print $6 }')


${BINDIR}/goal clerk multisig signprogram -p ${TEMPDIR}/true.teal -a ${ACCOUNT} -A ${ACCOUNTM} -o ${TEMPDIR}/mtrue.lsig

${BINDIR}/goal clerk multisig signprogram -L ${TEMPDIR}/mtrue.lsig -a ${ACCOUNTC}

${BINDIR}/goal clerk send --amount 1000000 --from ${ACCOUNT} --to ${ACCOUNTM}

${BINDIR}/goal clerk send --amount 200000 --from ${ACCOUNTM} --to ${ACCOUNTC} -L ${TEMPDIR}/mtrue.lsig

date '+e2e_teal OK %Y%m%d_%H%M%S'
