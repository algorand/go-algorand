#!/bin/bash

date '+keyreg-teal-test start %Y%m%d_%H%M%S'

set -e
set -x
set -o pipefail
export SHELLOPTS

WALLET=$1

gcmd="goal -w ${WALLET}"

ACCOUNT=$(${gcmd} account list|awk '{ print $3 }')
ACCOUNTA=$(${gcmd} account new|awk '{ print $6 }')
ACCOUNTB=$(${gcmd} account new|awk '{ print $6 }')
LEASE=YmxhaCBibGFoIGxlYXNlIHdoYXRldmVyIGJsYWghISE=

DUR=8
PERIOD=8
EXPIRE=10000
FEE=100000

echo "generating new delegate and participation keys for newly-funded account ${ACCOUNTA}"
${gcmd} clerk send --from ${ACCOUNT} --to ${ACCOUNTA} -a 1000000
DELKEY=$(algokey generate -f ${TEMPDIR}/delegate.keyregkey | grep "Public key" | awk '{ print $3 }')
algotmpl -d ${GOPATH}/src/github.com/algorand/go-algorand/tools/teal/templates/ delegate-key-registration --fee ${FEE} --dur ${DUR} --period ${PERIOD} --expire ${EXPIRE} --auth ${DELKEY} --lease ${LEASE} > ${TEMPDIR}/delegate.teal
${gcmd} clerk compile -a ${ACCOUNTA} -s -o ${TEMPDIR}/kr.lsig ${TEMPDIR}/delegate.teal

RES=$(${gcmd} account addpartkey -a ${ACCOUNTA} --roundFirstValid 0 --roundLastValid 100)
if [[ $RES != 'Participation key generation successful' ]]; then
    date '+keyreg-teal-test FAIL did not see confirmation that partkey gen was successful %Y%m%d_%H%M%S'
    false
fi

echo "wait for first round multiple"
ROUND=$(goal node status | grep 'Last committed block:'|awk '{ print $4 }')
cat<<EOF|python - > ${TEMPDIR}/pbound
print(((${ROUND} // ${PERIOD}) * ${PERIOD}) + ${PERIOD})
EOF
PBOUND=$(cat ${TEMPDIR}/pbound)
while [ ${ROUND} -lt ${PBOUND} ]; do
    goal node wait --waittime 30
    ROUND=$(goal node status | grep 'Last committed block:'|awk '{ print $4 }')
done

echo "send a bad keyreg transaction (missing lease)"
${gcmd} account changeonlinestatus -a ${ACCOUNTA} --online --firstvalid ${PBOUND} --validrounds `expr ${DUR} + 1` --txfile ${TEMPDIR}/keyreg.tx
dsign ${TEMPDIR}/delegate.keyregkey ${TEMPDIR}/kr.lsig < ${TEMPDIR}/keyreg.tx > ${TEMPDIR}/keyreg.stx

RES=$(${gcmd} clerk rawsend -f ${TEMPDIR}/keyreg.stx || true)
EXPERROR='rejected by logic'
if [[ $RES != *"${EXPERROR}"* ]]; then
    date '+keyreg-teal-test FAIL txn with missing lease preimage should be rejected %Y%m%d_%H%M%S'
    false
fi

echo "send a bad keyreg transaction (bad validity)"
${gcmd} account changeonlinestatus -a ${ACCOUNTA} --online --firstvalid ${PBOUND} --validrounds `expr ${DUR} + 4` --txfile ${TEMPDIR}/keyreg.tx
dsign ${TEMPDIR}/delegate.keyregkey ${TEMPDIR}/kr.lsig < ${TEMPDIR}/keyreg.tx > ${TEMPDIR}/keyreg.stx

RES=$(${gcmd} clerk rawsend -f ${TEMPDIR}/keyreg.stx || true)
EXPERROR='rejected by logic'
if [[ $RES != *"${EXPERROR}"* ]]; then
    date '+keyreg-teal-test FAIL txn with invalid validity window should be rejected %Y%m%d_%H%M%S'
    false
fi

echo "send a bad keyreg transaction (bad delegate key)"
${gcmd} account changeonlinestatus -a ${ACCOUNTA} -x ${LEASE} --online --firstvalid ${PBOUND} --validrounds `expr ${DUR} + 1` --txfile ${TEMPDIR}/keyreg.tx
algokey generate -f ${TEMPDIR}/bad.keyregkey
dsign ${TEMPDIR}/bad.keyregkey ${TEMPDIR}/kr.lsig < ${TEMPDIR}/keyreg.tx > ${TEMPDIR}/keyreg.stx

RES=$(${gcmd} clerk rawsend -f ${TEMPDIR}/keyreg.stx || true)
EXPERROR='rejected by logic'
if [[ $RES != *"${EXPERROR}"* ]]; then
    date '+keyreg-teal-test FAIL txn with incorrect delegate key should be rejected %Y%m%d_%H%M%S'
    false
fi

echo "send a correct keyreg transaction"
REGOK=$(${gcmd} account list | grep ${ACCOUNTA} | awk '{ print $1 }' | grep -c offline)
if [[ $REGOK != 1 ]]; then
   date '+keyreg-teal-test FAIL account is online before keyreg %Y%m%d_%H%M%S'
   false
fi

${gcmd} account changeonlinestatus -a ${ACCOUNTA} -x ${LEASE} --online --firstvalid ${PBOUND} --validrounds `expr ${DUR} + 1` --txfile ${TEMPDIR}/keyreg.tx
dsign ${TEMPDIR}/delegate.keyregkey ${TEMPDIR}/kr.lsig < ${TEMPDIR}/keyreg.tx > ${TEMPDIR}/keyreg.stx
${gcmd} clerk rawsend -f ${TEMPDIR}/keyreg.stx

REGOK=$(${gcmd} account list | grep ${ACCOUNTA} | awk '{ print $1 }' | grep -c online)
if [[ $REGOK != 1 ]]; then
   date '+keyreg-teal-test FAIL correct keyreg transaction failed %Y%m%d_%H%M%S'
   false
fi

echo "replay keyreg transaction with different fee"
${gcmd} account changeonlinestatus -a ${ACCOUNTA} -x ${LEASE} --online --firstvalid ${PBOUND} --validrounds `expr ${DUR} + 1` --txfile ${TEMPDIR}/keyreg.tx --fee 100000
dsign ${TEMPDIR}/delegate.keyregkey ${TEMPDIR}/kr.lsig < ${TEMPDIR}/keyreg.tx > ${TEMPDIR}/keyreg.stx

RES=$(${gcmd} clerk rawsend -f ${TEMPDIR}/keyreg.stx || true)
EXPERROR='using an overlapping lease'
if [[ $RES != *"${EXPERROR}"* ]]; then
    date '+keyreg-teal-test FAIL replayed txn should be rejected %Y%m%d_%H%M%S'
    false
fi

echo "generating new delegate and participation keys for newly-funded account ${ACCOUNTB}"

DUR=8
PERIOD=8
EXPIRE=10
FEE=100000

${gcmd} clerk send --from ${ACCOUNT} --to ${ACCOUNTB} -a 1000000
DELKEY=$(algokey generate -f ${TEMPDIR}/delegate.keyregkey | grep "Public key" | awk '{ print $3 }')
algotmpl -d ${GOPATH}/src/github.com/algorand/go-algorand/tools/teal/templates/ delegate-key-registration --fee ${FEE} --dur ${DUR} --period ${PERIOD} --expire ${EXPIRE} --auth ${DELKEY} --lease ${LEASE} > ${TEMPDIR}/delegate.teal
${gcmd} clerk compile -a ${ACCOUNTB} -s -o ${TEMPDIR}/kr.lsig ${TEMPDIR}/delegate.teal

RES=$(${gcmd} account addpartkey -a ${ACCOUNTB} --roundFirstValid 0 --roundLastValid 100)
if [[ $RES != 'Participation key generation successful' ]]; then
    date '+keyreg-teal-test FAIL did not see confirmation that partkey gen was successful %Y%m%d_%H%M%S'
    false
fi

echo "wait for valid duration to pass"
ROUND=$(goal node status | grep 'Last committed block:'|awk '{ print $4 }')
while [ ${ROUND} -lt `expr ${EXPIRE} + 1` ]; do
    goal node wait --waittime 30
    ROUND=$(goal node status | grep 'Last committed block:'|awk '{ print $4 }')
done

echo "send a keyreg transaction after expiration"
${gcmd} account changeonlinestatus -a ${ACCOUNTB} -x ${LEASE} --online --firstvalid ${PBOUND} --validrounds `expr ${DUR} + 1` --txfile ${TEMPDIR}/keyreg.tx
dsign ${TEMPDIR}/delegate.keyregkey ${TEMPDIR}/kr.lsig < ${TEMPDIR}/keyreg.tx > ${TEMPDIR}/keyreg.stx

RES=$(${gcmd} clerk rawsend -f ${TEMPDIR}/keyreg.stx || true)
EXPERROR='rejected by logic'
if [[ $RES != *"${EXPERROR}"* ]]; then
    date '+keyreg-teal-test FAIL keyreg on expired logic should be rejected %Y%m%d_%H%M%S'
    false
fi
