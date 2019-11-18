#!/bin/bash

date '+atomic-swap-teal-test start %Y%m%d_%H%M%S'

set -e
set -x
export GOPATH=$(go env GOPATH)

TEMPDIR=$(mktemp -d)
trap "rm -rf $TEMPDIR" 0

NETDIR=${TEMPDIR}/net

if [ ! -z $BINDIR ]; then
    export PATH=${BINDIR}:${PATH}
fi

goal network create -r ${NETDIR} -n tbd -t ${GOPATH}/src/github.com/algorand/go-algorand/test/testdata/nettemplates/TwoNodes50EachFuture.json

goal network start -r ${NETDIR}

# replaces prior trap0
trap "goal network stop -r ${NETDIR}; rm -rf ${TEMPDIR}" 0

export ALGORAND_DATA=${NETDIR}/Node

ACCOUNT=$(goal account list|awk '{ print $3 }')
ACCOUNTB=$(goal account new|awk '{ print $6 }')
ZERO_ADDRESS=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ
LEASE=YmxhaCBibGFoIGxlYXNlIHdoYXRldmVyIGJsYWghISE=

# Generate the template
algotmpl -d ${GOPATH}/src/github.com/algorand/go-algorand/tools/teal/templates/ atomic-swap --fee=2000 --hashfn="sha256" --hashimg="9S+9MrKzuG/4jvbEkGKChfSCrxXdyylUH5S89Saj9sc=" --own=${ACCOUNT} --rcv=${ACCOUNTB} --timeout=100000 > ${TEMPDIR}/atomic.teal

# Compile the template
CONTRACT=$(goal clerk compile ${TEMPDIR}/atomic.teal | awk '{ print $2 }')

# Fund the contract
goal clerk send -a 10000000 -f ${ACCOUNT} -t ${CONTRACT}

# Fail to release the funds using the wrong preimage
RES=$(goal clerk send --from-program ${TEMPDIR}/atomic.teal -a=0 -t=${ZERO_ADDRESS} --close-to=${ACCOUNTB} --argb64=YXNkZg== 2>&1 || true)
EXPERROR='rejected by logic'
if [[ $RES != *"${EXPERROR}"* ]]; then
    date '+atomic-swap-teal-test FAIL txn with wrong preimage should be rejected %Y%m%d_%H%M%S'
    false
fi

# Fail to release the funds using the right preimage but nonzero amount
RES=$(goal clerk send --from-program ${TEMPDIR}/atomic.teal -a=10 -t=${ZERO_ADDRESS} --close-to=${ACCOUNTB} --argb64=aHVudGVyMg== 2>&1 || true)
EXPERROR='rejected by logic'
if [[ $RES != *"${EXPERROR}"* ]]; then
    date '+atomic-swap-teal-test FAIL txn with nonzero amount should be rejected %Y%m%d_%H%M%S'
    false
fi

# Succeed in releasing the funds using the correct preimage
goal clerk send --fee=1000 --from-program ${TEMPDIR}/atomic.teal -a=0 -t=${ZERO_ADDRESS} --close-to=${ACCOUNTB} --argb64=aHVudGVyMg==

# Check balance
BALANCEB=$(goal account balance -a ${ACCOUNTB} | awk '{ print $1 }')
if [ $BALANCEB -ne 9999000 ]; then
    date '+atomic-swap-teal-test FAIL wanted balance=9999000 but got ${BALANCEB} %Y%m%d_%H%M%S'
    false
fi

date '+atomic-swap-teal-test OK %Y%m%d_%H%M%S'
