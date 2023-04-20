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

# First, try to send an extremely large "request" in the request body.
# This should fail with a 413 error.
# Some of our MacOS nightly tests fail for specifying the bs (block size)
# value in capital letters (i.e. 11M), so just specify it as 1024 bytes and
# allocate 11K blocks so we get a 11MB sized file.
dd if=/dev/zero of="${TEMPDIR}/tooLargeRequest.json" bs=1024 count=11000
RES=$(${gcmd} clerk simulate --request "${TEMPDIR}/tooLargeRequest.json" 2>&1 || true)
EXPERROR="simulation error: HTTP 413 Request Entity Too Large:"
if [[ $RES != *"${EXPERROR}"* ]]; then
    date '+app-simulate-test FAIL the simulate API should fail for request bodies exceeding 10MB %Y%m%d_%H%M%S'
    false
fi

##############################################
# WE FIRST TEST TRANSACTION GROUP SIMULATION #
##############################################

${gcmd} clerk send -a 10000 -f ${ACCOUNT} -t ${ACCOUNT} -o "${TEMPDIR}/pay1.tx"
${gcmd} clerk send -a 10000 -f ${ACCOUNT} -t ${ACCOUNT} -o "${TEMPDIR}/pay2.tx"

cat "${TEMPDIR}/pay1.tx" "${TEMPDIR}/pay2.tx" | ${gcmd} clerk group -i - -o "${TEMPDIR}/grouped.tx"

# We test transaction group simulation WITHOUT signatures
RES=$(${gcmd} clerk simulate -t "${TEMPDIR}/grouped.tx")

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
${gcmd} clerk split -i "${TEMPDIR}/grouped.tx" -o "${TEMPDIR}/grouped.tx"

${gcmd} clerk sign -i "${TEMPDIR}/grouped-0.tx" -o "${TEMPDIR}/grouped-0.stx"
${gcmd} clerk sign -i "${TEMPDIR}/grouped-1.tx" -o "${TEMPDIR}/grouped-1.stx"

cat "${TEMPDIR}/grouped-0.stx" "${TEMPDIR}/grouped-1.stx" > "${TEMPDIR}/grouped.stx"

RES=$(${gcmd} clerk simulate -t "${TEMPDIR}/grouped.stx" | jq '."would-succeed"')
if [[ $RES != $CONST_TRUE ]]; then
    date '+app-simulate-test FAIL should pass to simulate self pay transaction group %Y%m%d_%H%M%S'
    false
fi

# Test creating and using a simulate request object
${gcmd} clerk simulate -t "${TEMPDIR}/grouped.stx" --request-only-out "${TEMPDIR}/simulateRequest.json"

NUM_GROUPS=$(jq '."txn-groups" | length' < "${TEMPDIR}/simulateRequest.json")
if [ $NUM_GROUPS -ne 1 ]; then
    date '+app-simulate-test FAIL should have 1 transaction group in simulate request %Y%m%d_%H%M%S'
    false
fi

NUM_TXNS=$(jq '."txn-groups"[0]."txns" | length' < "${TEMPDIR}/simulateRequest.json")
if [ $NUM_TXNS -ne 2 ]; then
    date '+app-simulate-test FAIL should have 2 transactions in simulate request %Y%m%d_%H%M%S'
    false
fi

RES=$(${gcmd} clerk simulate --request "${TEMPDIR}/simulateRequest.json" | jq '."would-succeed"')
if [[ $RES != $CONST_TRUE ]]; then
    date '+app-simulate-test FAIL should pass with raw simulate request %Y%m%d_%H%M%S'
    false
fi

###############################################
# WE ALSO TEST OVERSPEND IN TRANSACTION GROUP #
###############################################

${gcmd} clerk send -a 1000000000000 -f ${ACCOUNT} -t ${ACCOUNT} -o "${TEMPDIR}/pay1.tx"
${gcmd} clerk send -a 10000 -f ${ACCOUNT} -t ${ACCOUNT} -o "${TEMPDIR}/pay2.tx"

cat "${TEMPDIR}/pay1.tx" "${TEMPDIR}/pay2.tx" | ${gcmd} clerk group -i - -o "${TEMPDIR}/grouped.tx"

${gcmd} clerk split -i "${TEMPDIR}/grouped.tx" -o "${TEMPDIR}/grouped.tx"

${gcmd} clerk sign -i "${TEMPDIR}/grouped-0.tx" -o "${TEMPDIR}/grouped-0.stx"
${gcmd} clerk sign -i "${TEMPDIR}/grouped-1.tx" -o "${TEMPDIR}/grouped-1.stx"

cat "${TEMPDIR}/grouped-0.stx" "${TEMPDIR}/grouped-1.stx" > "${TEMPDIR}/grouped.stx"

RES=$(${gcmd} clerk simulate -t "${TEMPDIR}/grouped.stx")

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
${gcmd} app method --method "empty()void" --app-id $APPID --from $ACCOUNT 2>&1 -o "${TEMPDIR}/empty.tx"

# SIMULATE without a signature first
RES=$(${gcmd} clerk simulate -t "${TEMPDIR}/empty.tx")

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
${gcmd} clerk sign -i "${TEMPDIR}/empty.tx" -o "${TEMPDIR}/empty.stx"
RES=$(${gcmd} clerk simulate -t "${TEMPDIR}/empty.stx" | jq '."would-succeed"')

# with signature, simulation app-call should succeed
if [[ $RES != $CONST_TRUE ]]; then
    date '+app-simulate-test FAIL the simulation call to empty()void should succeed %Y%m%d_%H%M%S'
    false
fi

###########################################################
# WE WANT TO FURTHER TEST UNLIMIT LOG IN SIMULATION WORKS #
###########################################################

TEAL=test/scripts/e2e_subs/tealprogs

printf '#pragma version 6\nint 1' > "${TEMPDIR}/simple-v6.teal"

# NOTE: logs-a-lot.teal contains a method that logs 1.4kb info, which is well over 1kb limit in binary
#       we test it here to see if the simulate unlimit log works under goal clerk simulate

RES=$(${gcmd} app create --creator ${ACCOUNT} --approval-prog "${TEAL}/logs-a-lot.teal" --clear-prog "${TEMPDIR}/simple-v6.teal" --global-byteslices 0 --global-ints 0 --local-byteslices 0 --local-ints 0 2>&1 || true)
EXPSUCCESS='Created app with app index'
if [[ $RES != *"${EXPSUCCESS}"* ]]; then
    date '+app-simulate-test FAIL the app creation for logs-a-lot.teal should succeed %Y%m%d_%H%M%S'
    false
fi

APPID=$(echo "$RES" | grep Created | awk '{ print $6 }')

# SIMULATION! without unlimiting log should call `small_log()void`
${gcmd} app method --method "small_log()void" --app-id $APPID --from $ACCOUNT 2>&1 -o "${TEMPDIR}/small_log.tx"
${gcmd} clerk sign -i "${TEMPDIR}/small_log.tx" -o "${TEMPDIR}/small_log.stx"
RES=$(${gcmd} clerk simulate -t "${TEMPDIR}/small_log.stx")

if [[ $(echo "$RES" | jq '."would-succeed"') != $CONST_TRUE ]]; then
    date '+app-simulate-test FAIL the app call to logs-a-lot.teal for small_log()void would-succeed should be true %Y%m%d_%H%M%S'
    false
fi

EXPECTED_SMALL_LOG='yet another ephemeral log'

if [[ $(echo "$RES" | jq '."txn-groups"[0]."txn-results"[0]."txn-result"."logs"[0] | @base64d') != *"${EXPECTED_SMALL_LOG}"* ]]; then
    date '+app-simulate-test FAIL the app call to logs-a-lot.teal for small_log()void should succeed %Y%m%d_%H%M%S'
    false
fi

if [[ $(echo "$RES" | jq '."eval-changes"') != null ]]; then
    date '+app-simulate-test FAIL the app call to logs-a-lot.teal without lift-log-limits should not return with eval-changes field %Y%m%d_%H%M%S'
    false
fi

${gcmd} app method --method "unlimited_log_test()void" --app-id $APPID --from $ACCOUNT 2>&1 -o "${TEMPDIR}/big_log.tx"
${gcmd} clerk sign -i "${TEMPDIR}/big_log.tx" -o "${TEMPDIR}/big_log.stx"
RES=$(${gcmd} clerk simulate -t "${TEMPDIR}/big_log.stx")

if [[ $(echo "$RES" | jq '."would-succeed"') != $CONST_FALSE ]]; then
    date '+app-simulate-test FAIL the app call to logs-a-lot.teal for unlimited_log_test()void would-succeed should be false without unlimiting log %Y%m%d_%H%M%S'
    false
fi

EXPECTED_FAILURE='logic eval error: too many log calls in program. up to 32 is allowed.'

if [[ $(echo "$RES" | jq '."txn-groups"[0]."failure-message"') != *"${EXPECTED_FAILURE}"* ]]; then
    date '+app-simulate-test FAIL the app call to logs-a-lot.teal for unlimited_log_test()void should fail without unlmited log option %Y%m%d_%H%M%S'
    false
fi

if [[ $(echo "$RES" | jq '."eval-changes"') != null ]]; then
    date '+app-simulate-test FAIL the app call to logs-a-lot.teal without lift-log-limits should not return with eval-changes field %Y%m%d_%H%M%S'
    false
fi

# SIMULATION! with unlimiting log should call `unlimited_log_test()void`
${gcmd} app method --method "unlimited_log_test()void" --app-id $APPID --from $ACCOUNT 2>&1 -o "${TEMPDIR}/big_log.tx"
${gcmd} clerk sign -i "${TEMPDIR}/big_log.tx" -o "${TEMPDIR}/big_log.stx"
RES=$(${gcmd} clerk simulate --lift-log-limits -t "${TEMPDIR}/big_log.stx")

if [[ $(echo "$RES" | jq '."would-succeed"') != $CONST_TRUE ]]; then
    date '+app-simulate-test FAIL the app call to logs-a-lot.teal for unlimited_log_test()void would-succeed should be true with unlimiting log %Y%m%d_%H%M%S'
    false
fi

if [[ $(echo "$RES" | jq '."txn-groups"[0]."failed-at"') != null ]]; then
    date '+app-simulate-test FAIL the app call to logs-a-lot.teal for unlimited_log_test()void should succeed with unlmited log option %Y%m%d_%H%M%S'
    false
fi

if [[ $(echo "$RES" | jq '."eval-changes"."log-limits"."max-log-size"') -ne 65536 ]]; then
    date '+app-simulate-test FAIL the app call to logs-a-lot.teal with unlimited log should return max log size 65536 %Y%m%d_%H%M%S'
    false
fi

if [[ $(echo "$RES" | jq '."eval-changes"."log-limits"."max-log-calls"') -ne 2048 ]]; then
    date '+app-simulate-test FAIL the app call to logs-a-lot.teal with unlimited log should return max log calls 2048 %Y%m%d_%H%M%S'
    false
fi

EXPECTED_FIRST_LINE_BIG_LOG='The time has come,'

if [[ $(echo "$RES" | jq '."txn-groups"[0]."txn-results"[0]."txn-result"."logs"[0] | @base64d') != *"${EXPECTED_FIRST_LINE_BIG_LOG}"* ]]; then
    date '+app-simulate-test FAIL the app call to logs-a-lot.teal for unlimited_log_test()void should succeed %Y%m%d_%H%M%S'
    false
fi

EXPECTED_LAST_LINE_BIG_LOG='Those of the largest size,'

if [[ $(echo "$RES" | jq '."txn-groups"[0]."txn-results"[0]."txn-result"."logs"[-1] | @base64d') != *"${EXPECTED_LAST_LINE_BIG_LOG}"* ]]; then
    date '+app-simulate-test FAIL the app call to logs-a-lot.teal for unlimited_log_test()void should succeed %Y%m%d_%H%M%S'
    false
fi
