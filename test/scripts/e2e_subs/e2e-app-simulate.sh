#!/bin/bash

date '+app-simulate-test start %Y%m%d_%H%M%S'

set -e
set -x
set -o pipefail
set -o nounset
export SHELLOPTS

WALLET=$1

# Directory of this bash program
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

gcmd="goal -w ${WALLET}"

ACCOUNT=$(${gcmd} account list|awk '{ print $3 }')

CONST_TRUE="true"
CONST_FALSE="false"

# First, try to send an extremely large "transaction" in the request body.
# This should fail with a 413 error.
dd if=/dev/zero of=${TEMPDIR}/toolarge.tx bs=11M count=1
RES=$(${gcmd} clerk simulate -t "${TEMPDIR}/toolarge.tx" 2>&1 || true)
EXPERROR="simulation error: HTTP 413 Request Entity Too Large:"
if [[ $RES != *"${EXPERROR}"* ]]; then
    date '+app-simulate-test FAIL the simulate API should fail for request bodies exceeding 10MB %Y%m%d_%H%M%S'
    false
fi

##############################################
# WE FIRST TEST TRANSACTION GROUP SIMULATION #
##############################################

${gcmd} clerk send -a 10000 -f ${ACCOUNT} -t ${ACCOUNT} -o pay1.tx
${gcmd} clerk send -a 10000 -f ${ACCOUNT} -t ${ACCOUNT} -o pay2.tx

cat pay1.tx pay2.tx | ${gcmd} clerk group -i - -o grouped.tx

# We test transaction group simulation WITHOUT signatures
RES=$(${gcmd} clerk simulate -t grouped.tx)

if [[ $(echo "$RES" | jq '."would-succeed"') != $CONST_FALSE ]]; then
    date '+app-simulate-test FAIL the simulation transaction group without signatures should not succeed %Y%m%d_%H%M%S'
    false
fi

# check the simulation failing reason, first transaction has no signature
if [[ $(echo "$RES" | jq '."txn-groups"[0]."txn-results"[0]."missing-signature"') != $CONST_TRUE ]]; then
    date '+app-simulate-test FAIL the simulation transaction group FAIL for first transaction has NO signature %Y%m%d_%H%M%S'
    false
fi

# check the simulation failing reason, second transaction has no signature
if [[ $(echo "$RES" | jq '."txn-groups"[0]."txn-results"[1]."missing-signature"') != $CONST_TRUE ]]; then
    date '+app-simulate-test FAIL the simulation transaction group FAIL for second transaction has NO signature %Y%m%d_%H%M%S'
    false
fi

# We then test transaction group simulation WITH signatures
${gcmd} clerk split -i grouped.tx -o grouped.tx

${gcmd} clerk sign -i grouped-0.tx -o grouped-0.stx
${gcmd} clerk sign -i grouped-1.tx -o grouped-1.stx

cat grouped-0.stx grouped-1.stx > grouped.stx

RES=$(${gcmd} clerk simulate -t grouped.stx | jq '."would-succeed"')

if [[ $RES != $CONST_TRUE ]]; then
    date '+app-simulate-test FAIL should pass to simulate self pay transaction group %Y%m%d_%H%M%S'
    false
fi

###############################################
# WE ALSO TEST OVERSPEND IN TRANSACTION GROUP #
###############################################

${gcmd} clerk send -a 1000000000000 -f ${ACCOUNT} -t ${ACCOUNT} -o pay1.tx
${gcmd} clerk send -a 10000 -f ${ACCOUNT} -t ${ACCOUNT} -o pay2.tx

cat pay1.tx pay2.tx | ${gcmd} clerk group -i - -o grouped.tx

${gcmd} clerk split -i grouped.tx -o grouped.tx

${gcmd} clerk sign -i grouped-0.tx -o grouped-0.stx
${gcmd} clerk sign -i grouped-1.tx -o grouped-1.stx

cat grouped-0.stx grouped-1.stx > grouped.stx

RES=$(${gcmd} clerk simulate -t grouped.stx)

if [[ $(echo "$RES" | jq '."would-succeed"') != $CONST_FALSE ]]; then
    data '+app-simulate-test FAIL should FAIL for overspending in simulate self pay transaction group %Y%m%d_%H%M%S'
    false
fi

OVERSPEND_INFO="overspend"

if [[ $(echo "$RES" | jq '."txn-groups"[0]."failure-message"') != *"$OVERSPEND_INFO"* ]]; then
    data '+app-simulate-test FAIL first overspending transaction in transaction group should contain message OVERSPEND %Y%m%d_%H%M%S'
    false
fi

#######################################################
# NOW WE TRY TO TEST SIMULATION WITH ABI METHOD CALLS #
#######################################################

printf '#pragma version 2\nint 1' > "${TEMPDIR}/simple-v2.teal"

# Real Create
RES=$(${gcmd} app method --method "create(uint64)uint64" --arg "1234" --create --approval-prog ${DIR}/tealprogs/app-abi-method-example.teal --clear-prog ${TEMPDIR}/simple-v2.teal --global-byteslices 0 --global-ints 0 --local-byteslices 1 --local-ints 0 --extra-pages 0 --from $ACCOUNT 2>&1 || true)
EXPECTED="method create(uint64)uint64 succeeded with output: 2468"
if [[ $RES != *"${EXPECTED}"* ]]; then
    date '+app-simulate-test FAIL the method call to create(uint64)uint64 should not fail %Y%m%d_%H%M%S'
    false
fi

APPID=$(echo "$RES" | grep Created | awk '{ print $6 }')

# SIMULATION! empty()void
${gcmd} app method --method "empty()void" --app-id $APPID --from $ACCOUNT 2>&1 -o empty.tx

# SIMULATE without a signature first
RES=$(${gcmd} clerk simulate -t empty.tx)

# confirm that without signature, the simulation should fail
if [[ $(echo "$RES" | jq '."would-succeed"') != $CONST_FALSE ]]; then
    date '+app-simulate-test FAIL the simulation call to empty()void without signature should not succeed %Y%m%d_%H%M%S'
    false
fi

# check again the simulation failing reason
if [[ $(echo "$RES" | jq '."txn-groups"[0]."txn-results"[0]."missing-signature"') != $CONST_TRUE ]]; then
    date '+app-simulate-test FAIL the simulation call to empty()void without signature should fail with missing-signature %Y%m%d_%H%M%S'
    false
fi

# SIMULATE with a signature
${gcmd} clerk sign -i empty.tx -o empty.stx
RES=$(${gcmd} clerk simulate -t empty.stx | jq '."would-succeed"')

# with signature, simulation app-call should succeed
if [[ $RES != $CONST_TRUE ]]; then
    date '+app-simulate-test FAIL the simulation call to empty()void should succeed %Y%m%d_%H%M%S'
    false
fi
