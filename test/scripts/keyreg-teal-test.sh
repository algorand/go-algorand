#!/bin/bash

date '+keyreg-teal-test start %Y%m%d_%H%M%S'

set -e
set -x
export GOPATH=$(go env GOPATH)

TEMPDIR=$(mktemp -d)
trap "rm -rf $TEMPDIR" 0

NETDIR=${TEMPDIR}/net
PROJROOT=${GOPATH}/src/github.com/algorand/go-algorand

if [ ! -z $BINDIR ]; then
    export PATH=${BINDIR}:${PATH}
fi

goal network create -r ${NETDIR} -n tbd -t ${PROJROOT}/test/testdata/nettemplates/TwoNodes50EachFuture.json
goal network start -r ${NETDIR}

# replaces prior trap0
trap "goal network stop -r ${NETDIR}; rm -rf ${TEMPDIR}" 0

export ALGORAND_DATA=${NETDIR}/Node

ACCOUNT=$(goal account list|awk '{ print $3 }')
ACCOUNTA=$(goal account new|awk '{ print $6 }')
ACCOUNTB=$(goal account new|awk '{ print $6 }')
LEASE=YmxhaCBibGFoIGxlYXNlIHdoYXRldmVyIGJsYWghISE=

DUR=4
PERIOD=4
EXPIRE=10000
FEE=100000

echo "generating new delegate and participation keys for newly-funded account ${ACCOUNTA}"
goal clerk send --from ${ACCOUNT} --to ${ACCOUNTA} -a 1000000
DELKEY=$(algokey generate -f ${TEMPDIR}/delegate.keyregkey | grep "Public key" | awk '{ print $3 }')
algotmpl -d ${PROJROOT}/tools/teal/templates/ delegate-key-registration --fee ${FEE} --dur ${DUR} --period ${PERIOD} --expire ${EXPIRE} --auth ${DELKEY} --lease ${LEASE} > ${TEMPDIR}/delegate.teal
goal clerk compile -a ${ACCOUNTA} -s -o ${TEMPDIR}/kr.lsig ${TEMPDIR}/delegate.teal

RES=$(goal account addpartkey -a ${ACCOUNTA} --roundFirstValid 0 --roundLastValid 100)
if [[ $RES != 'Participation key generation successful' ]]; then
    date '+keyreg-teal-test FAIL did not see confirmation that partkey gen was successful %Y%m%d_%H%M%S'
    false
fi

echo "wait for first round multiple"
ROUND=$(goal node status | grep 'Last committed block:'|awk '{ print $4 }')
while [ ${ROUND} != ${PERIOD} ]; do
    goal node wait
    ROUND=$(goal node status | grep 'Last committed block:'|awk '{ print $4 }')
done

echo "send a bad keyreg transaction (missing lease)"
goal account changeonlinestatus -a ${ACCOUNTA} --online --firstvalid ${PERIOD} --validrounds `expr ${DUR} + 1` --txfile ${TEMPDIR}/keyreg.tx
dsign ${TEMPDIR}/delegate.keyregkey ${TEMPDIR}/kr.lsig < ${TEMPDIR}/keyreg.tx > ${TEMPDIR}/keyreg.stx

RES=$(goal clerk rawsend -f ${TEMPDIR}/keyreg.stx || true)
EXPERROR='rejected by logic'
if [[ $RES != *"${EXPERROR}"* ]]; then
    date '+keyreg-teal-test FAIL txn with missing lease preimage should be rejected %Y%m%d_%H%M%S'
    false
fi

echo "send a bad keyreg transaction (bad validity)"
goal account changeonlinestatus -a ${ACCOUNTA} --online --firstvalid ${PERIOD} --validrounds `expr ${DUR} + 4` --txfile ${TEMPDIR}/keyreg.tx
dsign ${TEMPDIR}/delegate.keyregkey ${TEMPDIR}/kr.lsig < ${TEMPDIR}/keyreg.tx > ${TEMPDIR}/keyreg.stx

RES=$(goal clerk rawsend -f ${TEMPDIR}/keyreg.stx || true)
EXPERROR='rejected by logic'
if [[ $RES != *"${EXPERROR}"* ]]; then
    date '+keyreg-teal-test FAIL txn with invalid validity window should be rejected %Y%m%d_%H%M%S'
    false
fi

echo "send a bad keyreg transaction (bad delegate key)"
goal account changeonlinestatus -a ${ACCOUNTA} -x ${LEASE} --online --firstvalid ${PERIOD} --validrounds `expr ${DUR} + 1` --txfile ${TEMPDIR}/keyreg.tx
algokey generate -f ${TEMPDIR}/bad.keyregkey
dsign ${TEMPDIR}/bad.keyregkey ${TEMPDIR}/kr.lsig < ${TEMPDIR}/keyreg.tx > ${TEMPDIR}/keyreg.stx

RES=$(goal clerk rawsend -f ${TEMPDIR}/keyreg.stx || true)
EXPERROR='rejected by logic'
if [[ $RES != *"${EXPERROR}"* ]]; then
    date '+keyreg-teal-test FAIL txn with incorrect delegate key should be rejected %Y%m%d_%H%M%S'
    false
fi

echo "send a correct keyreg transaction"
REGOK=$(goal account list | grep ${ACCOUNTA} | awk '{ print $1 }' | grep -c offline)
if [[ $REGOK != 1 ]]; then
   date '+keyreg-teal-test FAIL account is online before keyreg %Y%m%d_%H%M%S'
   false
fi

goal account changeonlinestatus -a ${ACCOUNTA} -x ${LEASE} --online --firstvalid ${PERIOD} --validrounds `expr ${DUR} + 1` --txfile ${TEMPDIR}/keyreg.tx
dsign ${TEMPDIR}/delegate.keyregkey ${TEMPDIR}/kr.lsig < ${TEMPDIR}/keyreg.tx > ${TEMPDIR}/keyreg.stx
goal clerk rawsend -f ${TEMPDIR}/keyreg.stx

REGOK=$(goal account list | grep ${ACCOUNTA} | awk '{ print $1 }' | grep -c online)
if [[ $REGOK != 1 ]]; then
   date '+keyreg-teal-test FAIL correct keyreg transaction failed %Y%m%d_%H%M%S'
   false
fi

echo "replay keyreg transaction with different fee"
goal account changeonlinestatus -a ${ACCOUNTA} -x ${LEASE} --online --firstvalid ${PERIOD} --validrounds `expr ${DUR} + 1` --txfile ${TEMPDIR}/keyreg.tx --fee 100000
dsign ${TEMPDIR}/delegate.keyregkey ${TEMPDIR}/kr.lsig < ${TEMPDIR}/keyreg.tx > ${TEMPDIR}/keyreg.stx

RES=$(goal clerk rawsend -f ${TEMPDIR}/keyreg.stx || true)
EXPERROR='already in ledger'
if [[ $RES != *"${EXPERROR}"* ]]; then
    date '+keyreg-teal-test FAIL replayed txn should be rejected %Y%m%d_%H%M%S'
    false
fi

echo "generating new delegate and participation keys for newly-funded account ${ACCOUNTB}"

DUR=8
PERIOD=8
EXPIRE=10
FEE=100000

goal clerk send --from ${ACCOUNT} --to ${ACCOUNTB} -a 1000000
DELKEY=$(algokey generate -f ${TEMPDIR}/delegate.keyregkey | grep "Public key" | awk '{ print $3 }')
algotmpl -d ${PROJROOT}/tools/teal/templates/ delegate-key-registration --fee ${FEE} --dur ${DUR} --period ${PERIOD} --expire ${EXPIRE} --auth ${DELKEY} --lease ${LEASE} > ${TEMPDIR}/delegate.teal
goal clerk compile -a ${ACCOUNTB} -s -o ${TEMPDIR}/kr.lsig ${TEMPDIR}/delegate.teal

RES=$(goal account addpartkey -a ${ACCOUNTB} --roundFirstValid 0 --roundLastValid 100)
if [[ $RES != 'Participation key generation successful' ]]; then
    date '+keyreg-teal-test FAIL did not see confirmation that partkey gen was successful %Y%m%d_%H%M%S'
    false
fi

echo "wait for valid duration to pass"
ROUND=$(goal node status | grep 'Last committed block:'|awk '{ print $4 }')
while [ ${ROUND} != `expr ${EXPIRE} + 1` ]; do
    goal node wait
    ROUND=$(goal node status | grep 'Last committed block:'|awk '{ print $4 }')
done

echo "send a keyreg transaction after expiration"
goal account changeonlinestatus -a ${ACCOUNTB} -x ${LEASE} --online --firstvalid ${PERIOD} --validrounds `expr ${DUR} + 1` --txfile ${TEMPDIR}/keyreg.tx
dsign ${TEMPDIR}/delegate.keyregkey ${TEMPDIR}/kr.lsig < ${TEMPDIR}/keyreg.tx > ${TEMPDIR}/keyreg.stx

RES=$(goal clerk rawsend -f ${TEMPDIR}/keyreg.stx || true)
EXPERROR='rejected by logic'
if [[ $RES != *"${EXPERROR}"* ]]; then
    date '+keyreg-teal-test FAIL keyreg on expired logic should be rejected %Y%m%d_%H%M%S'
    false
fi


