#!/bin/bash

date '+htlc-teal-test start %Y%m%d_%H%M%S'

my_dir="$(dirname "$0")"
source "$my_dir/rest.sh" "$@"

set -e
set -x
set -o pipefail
export SHELLOPTS

WALLET=$1

gcmd="goal -w ${WALLET}"

# Get network's minimum fee
MIN_FEE=$(get_min_fee)
echo "Network MinFee: $MIN_FEE"

ACCOUNT=$(${gcmd} account list|awk '{ print $3 }')
ACCOUNTB=$(${gcmd} account new|awk '{ print $6 }')
ZERO_ADDRESS=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ
LEASE=YmxhaCBibGFoIGxlYXNlIHdoYXRldmVyIGJsYWghISE=

# Generate the template
algotmpl -d tools/teal/templates/ htlc --fee=$((MIN_FEE * 2)) --hashfn="sha256" --hashimg="9S+9MrKzuG/4jvbEkGKChfSCrxXdyylUH5S89Saj9sc=" --own=${ACCOUNT} --rcv=${ACCOUNTB} --timeout=100000 > ${TEMPDIR}/atomic.teal

# Compile the template
CONTRACT=$(${gcmd} clerk compile ${TEMPDIR}/atomic.teal | awk '{ print $2 }')

# Fund the contract
${gcmd} clerk send -a 10000000 -f ${ACCOUNT} -t ${CONTRACT}

# Fail to release the funds using the wrong preimage
RES=$(${gcmd} clerk send --from-program ${TEMPDIR}/atomic.teal -a=0 -t=${ZERO_ADDRESS} --close-to=${ACCOUNTB} --argb64=YXNkZg== 2>&1 || true)
EXPERROR='rejected by logic'
if [[ $RES != *"${EXPERROR}"* ]]; then
    date '+htlc-teal-test FAIL txn with wrong preimage should be rejected %Y%m%d_%H%M%S'
    false
fi

# Fail to release the funds using the right preimage but nonzero amount
RES=$(${gcmd} clerk send --from-program ${TEMPDIR}/atomic.teal -a=10 -t=${ZERO_ADDRESS} --close-to=${ACCOUNTB} --argb64=aHVudGVyMg== 2>&1 || true)
EXPERROR='rejected by logic'
if [[ $RES != *"${EXPERROR}"* ]]; then
    date '+htlc-teal-test FAIL txn with nonzero amount should be rejected %Y%m%d_%H%M%S'
    false
fi

# Succeed in releasing the funds using the correct preimage
${gcmd} clerk send --fee=${MIN_FEE} --from-program ${TEMPDIR}/atomic.teal -a=0 -t=${ZERO_ADDRESS} --close-to=${ACCOUNTB} --argb64=aHVudGVyMg==

# Check balance
BALANCEB=$(${gcmd} account balance -a ${ACCOUNTB} | awk '{ print $1 }')
# Expected balance is 10000000 - MIN_FEE (account for rewards which may have accumulated)
EXPECTED_MIN=$((10000000 - MIN_FEE))
if [ $BALANCEB -lt $EXPECTED_MIN ]; then
    date "+htlc-teal-test FAIL wanted balance>=$EXPECTED_MIN but got ${BALANCEB} %Y%m%d_%H%M%S"
    false
fi

date '+htlc-teal-test OK %Y%m%d_%H%M%S'
