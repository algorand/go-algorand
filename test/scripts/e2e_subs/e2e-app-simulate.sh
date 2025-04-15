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

# We test transaction group simulation WITHOUT signatures with default arguments
RES=$(${gcmd} clerk simulate -t "${TEMPDIR}/grouped.tx")
if [[ $(echo "$RES" | jq '."txn-groups" | any(has("failure-message"))') != $CONST_TRUE ]]; then
    date '+app-simulate-test FAIL the simulation transaction group without signatures not fail %Y%m%d_%H%M%S'
    false
fi

# We test transaction group simulation WITHOUT signatures, but with allow-empty-signatures enabled
RES=$(${gcmd} clerk simulate --allow-empty-signatures -t "${TEMPDIR}/grouped.tx")
if [[ $(echo "$RES" | jq '."txn-groups" | any(has("failure-message"))') != $CONST_FALSE ]]; then
    date '+app-simulate-test FAIL the simulation transaction group without signatures should not fail when allow-empty-signatures is true %Y%m%d_%H%M%S'
    false
fi

# check the simulation eval overrides reports the right value
if [[ $(echo "$RES" | jq '."eval-overrides"."allow-empty-signatures"') != $CONST_TRUE ]]; then
    date '+app-simulate-test FAIL the simulation response should report eval overrides %Y%m%d_%H%M%S'
    false
fi

# We then test transaction group simulation WITH signatures
${gcmd} clerk split -i "${TEMPDIR}/grouped.tx" -o "${TEMPDIR}/grouped.tx"

${gcmd} clerk sign -i "${TEMPDIR}/grouped-0.tx" -o "${TEMPDIR}/grouped-0.stx"
${gcmd} clerk sign -i "${TEMPDIR}/grouped-1.tx" -o "${TEMPDIR}/grouped-1.stx"

cat "${TEMPDIR}/grouped-0.stx" "${TEMPDIR}/grouped-1.stx" > "${TEMPDIR}/grouped.stx"

RES=$(${gcmd} clerk simulate -t "${TEMPDIR}/grouped.stx")
if [[ $(echo "$RES" | jq '."txn-groups" | any(has("failure-message"))') != $CONST_FALSE ]]; then
    date '+app-simulate-test FAIL should pass to simulate self pay transaction group %Y%m%d_%H%M%S'
    false
fi

if [[ $(echo "$RES" | jq 'has("eval-overrides")') != $CONST_FALSE ]]; then
    date '+app-simulate-test FAIL the simulation response should not report eval overrides %Y%m%d_%H%M%S'
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

RES=$(${gcmd} clerk simulate --request "${TEMPDIR}/simulateRequest.json" | jq '."txn-groups" | any(has("failure-message"))')
if [[ $RES != $CONST_FALSE ]]; then
    date '+app-simulate-test FAIL should pass with raw simulate request %Y%m%d_%H%M%S'
    false
fi

###############################################
# WE ALSO TEST OVERSPEND IN TRANSACTION GROUP #
###############################################

${gcmd} clerk send -a 1000000000000000 -f ${ACCOUNT} -t ${ACCOUNT} -o "${TEMPDIR}/pay1.tx"
${gcmd} clerk send -a 10000 -f ${ACCOUNT} -t ${ACCOUNT} -o "${TEMPDIR}/pay2.tx"

cat "${TEMPDIR}/pay1.tx" "${TEMPDIR}/pay2.tx" | ${gcmd} clerk group -i - -o "${TEMPDIR}/grouped.tx"

${gcmd} clerk split -i "${TEMPDIR}/grouped.tx" -o "${TEMPDIR}/grouped.tx"

${gcmd} clerk sign -i "${TEMPDIR}/grouped-0.tx" -o "${TEMPDIR}/grouped-0.stx"
${gcmd} clerk sign -i "${TEMPDIR}/grouped-1.tx" -o "${TEMPDIR}/grouped-1.stx"

cat "${TEMPDIR}/grouped-0.stx" "${TEMPDIR}/grouped-1.stx" > "${TEMPDIR}/grouped.stx"

RES=$(${gcmd} clerk simulate -t "${TEMPDIR}/grouped.stx")

if [[ $(echo "$RES" | jq '."txn-groups" | any(has("failure-message"))') != $CONST_TRUE ]]; then
    date '+app-simulate-test FAIL should FAIL for overspending in simulate self pay transaction group %Y%m%d_%H%M%S'
    false
fi

OVERSPEND_INFO="overspend"

if [[ $(echo "$RES" | jq '."txn-groups"[0]."failure-message"') != *"$OVERSPEND_INFO"* ]]; then
    date '+app-simulate-test FAIL first overspending transaction in transaction group should contain message OVERSPEND %Y%m%d_%H%M%S'
    false
fi

#######################################################
# NOW WE TRY TO TEST SIMULATION WITH ABI METHOD CALLS #
#######################################################

printf '#pragma version 2\nint 1' > "${TEMPDIR}/simple-v2.teal"

# Real Create
RES=$(${gcmd} app method --method "create(uint64)uint64" --arg "1234" --create --approval-prog ${DIR}/tealprogs/app-abi-method-example.teal --clear-prog ${TEMPDIR}/simple-v2.teal --local-byteslices 1 --from $ACCOUNT 2>&1 || true)
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
# confirm that without signature, the simulation should fail with default args
if [[ $(echo "$RES" | jq '."txn-groups" | any(has("failure-message"))') != $CONST_TRUE ]]; then
    date '+app-simulate-test FAIL the simulation call to empty()void without signature should not succeed %Y%m%d_%H%M%S'
    false
fi

RES=$(${gcmd} clerk simulate --allow-empty-signatures -t "${TEMPDIR}/empty.tx")
# confirm that without signature, the simulation should pass with allow-empty-signatures
if [[ $(echo "$RES" | jq '."txn-groups" | any(has("failure-message"))') != $CONST_FALSE ]]; then
    date '+app-simulate-test FAIL the simulation call to empty()void without signature should succeed with allow-empty-signatures %Y%m%d_%H%M%S'
    false
fi

# check the simulation eval overrides reports the right value
if [[ $(echo "$RES" | jq '."eval-overrides"."allow-empty-signatures"') != $CONST_TRUE ]]; then
    date '+app-simulate-test FAIL the simulation call to empty()void without signature should report eval overrides %Y%m%d_%H%M%S'
    false
fi

# SIMULATE with a signature
${gcmd} clerk sign -i "${TEMPDIR}/empty.tx" -o "${TEMPDIR}/empty.stx"
RES=$(${gcmd} clerk simulate -t "${TEMPDIR}/empty.stx")

# with signature, simulation app-call should succeed
if [[ $(echo "$RES" | jq '."txn-groups" | any(has("failure-message"))') != $CONST_FALSE ]]; then
    date '+app-simulate-test FAIL the simulation call to empty()void should succeed %Y%m%d_%H%M%S'
    false
fi

if [[ $(echo "$RES" | jq 'has("eval-overrides")') != $CONST_FALSE ]]; then
    date '+app-simulate-test FAIL the simulation call to empty()void should not report eval overrides %Y%m%d_%H%M%S'
    false
fi

###########################################################
# WE WANT TO FURTHER TEST UNLIMIT LOG IN SIMULATION WORKS #
###########################################################

TEAL=test/scripts/e2e_subs/tealprogs

printf '#pragma version 6\nint 1' > "${TEMPDIR}/simple-v6.teal"

# NOTE: logs-a-lot.teal contains a method that logs 1.4kb info, which is well over 1kb limit in binary
#       we test it here to see if the simulate unlimit log works under goal clerk simulate

RES=$(${gcmd} app create --creator ${ACCOUNT} --approval-prog "${TEAL}/logs-a-lot.teal" --clear-prog "${TEMPDIR}/simple-v6.teal" 2>&1 || true)
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

if [[ $(echo "$RES" | jq '."txn-groups" | any(has("failure-message"))') != $CONST_FALSE ]]; then
    date '+app-simulate-test FAIL the app call to logs-a-lot.teal for small_log()void should not fail %Y%m%d_%H%M%S'
    false
fi

EXPECTED_SMALL_LOG='yet another ephemeral log'

if [[ $(echo "$RES" | jq '."txn-groups"[0]."txn-results"[0]."txn-result"."logs"[0] | @base64d') != *"${EXPECTED_SMALL_LOG}"* ]]; then
    date '+app-simulate-test FAIL the app call to logs-a-lot.teal for small_log()void should have expected logs %Y%m%d_%H%M%S'
    false
fi

if [[ $(echo "$RES" | jq 'has("eval-overrides")') != $CONST_FALSE ]]; then
    date '+app-simulate-test FAIL the app call to logs-a-lot.teal without allow-more-logging should not return with eval-overrides field %Y%m%d_%H%M%S'
    false
fi

${gcmd} app method --method "unlimited_log_test()void" --app-id $APPID --from $ACCOUNT 2>&1 -o "${TEMPDIR}/big_log.tx"
${gcmd} clerk sign -i "${TEMPDIR}/big_log.tx" -o "${TEMPDIR}/big_log.stx"
RES=$(${gcmd} clerk simulate -t "${TEMPDIR}/big_log.stx")

if [[ $(echo "$RES" | jq '."txn-groups" | any(has("failure-message"))') != $CONST_TRUE ]]; then
    date '+app-simulate-test FAIL the app call to logs-a-lot.teal for unlimited_log_test()void would-succeed should be false without unlimiting log %Y%m%d_%H%M%S'
    false
fi

EXPECTED_FAILURE='logic eval error: too many log calls in program. up to 32 is allowed.'

if [[ $(echo "$RES" | jq '."txn-groups"[0]."failure-message"') != *"${EXPECTED_FAILURE}"* ]]; then
    date '+app-simulate-test FAIL the app call to logs-a-lot.teal for unlimited_log_test()void should fail without unlmited log option %Y%m%d_%H%M%S'
    false
fi

if [[ $(echo "$RES" | jq 'has("eval-overrides")') != $CONST_FALSE ]]; then
    date '+app-simulate-test FAIL the app call to logs-a-lot.teal without allow-more-logging should not return with eval-overrides field %Y%m%d_%H%M%S'
    false
fi

# SIMULATION! with unlimiting log should call `unlimited_log_test()void`
${gcmd} app method --method "unlimited_log_test()void" --app-id $APPID --from $ACCOUNT 2>&1 -o "${TEMPDIR}/big_log.tx"
${gcmd} clerk sign -i "${TEMPDIR}/big_log.tx" -o "${TEMPDIR}/big_log.stx"
RES=$(${gcmd} clerk simulate --allow-more-logging -t "${TEMPDIR}/big_log.stx")

if [[ $(echo "$RES" | jq '."txn-groups" | any(has("failure-message"))') != $CONST_FALSE ]]; then
    date '+app-simulate-test FAIL the app call to logs-a-lot.teal for unlimited_log_test()void should not fail with unlimiting log %Y%m%d_%H%M%S'
    false
fi

if [[ $(echo "$RES" | jq '."txn-groups"[0]."failed-at"') != null ]]; then
    date '+app-simulate-test FAIL the app call to logs-a-lot.teal for unlimited_log_test()void should succeed with unlmited log option %Y%m%d_%H%M%S'
    false
fi

if [[ $(echo "$RES" | jq '."eval-overrides"."max-log-size"') -ne 65536 ]]; then
    date '+app-simulate-test FAIL the app call to logs-a-lot.teal with unlimited log should return max log size 65536 %Y%m%d_%H%M%S'
    false
fi

if [[ $(echo "$RES" | jq '."eval-overrides"."max-log-calls"') -ne 2048 ]]; then
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

############################################################
# WE WANT TO FURTHER TEST EXTRA BUDGET IN SIMULATION WORKS #
############################################################

function generate_teal() {
    FILE=$1
    VERSION=$2
    REPETITION=$3

    printf '#pragma version %d\n txn ApplicationID\n bz end\n' $VERSION > "${FILE}"

    # iterating in interval [0, REPETITION - 1]
    for i in $(seq 0 1 $(expr $REPETITION - 1)); do
        printf "int 1\npop\n" >> "${FILE}"
    done

    printf "end:\n int 1\n" >> "${FILE}"
}

BIG_TEAL_FILE="$TEMPDIR/int-pop-400-cost-a-lot.teal"
generate_teal "$BIG_TEAL_FILE" 8 400

printf '#pragma version 8\nint 1' > "${TEMPDIR}/simple-v8.teal"

RES=$(${gcmd} app create --creator ${ACCOUNT} --approval-prog "${BIG_TEAL_FILE}" --clear-prog "${TEMPDIR}/simple-v8.teal" --extra-pages 1 2>&1 || true)
EXPSUCCESS='Created app with app index'
if [[ $RES != *"${EXPSUCCESS}"* ]]; then
    date '+app-simulate-test FAIL the app creation for generated large TEAL should succeed %Y%m%d_%H%M%S'
    false
fi

APPID=$(echo "$RES" | grep Created | awk '{ print $6 }')

# SIMULATION! without extra budget should fail direct call
${gcmd} app call --app-id $APPID --from $ACCOUNT 2>&1 -o "${TEMPDIR}/no-extra-opcode-budget.tx"
${gcmd} clerk sign -i "${TEMPDIR}/no-extra-opcode-budget.tx" -o "${TEMPDIR}/no-extra-opcode-budget.stx"
RES=$(${gcmd} clerk simulate -t "${TEMPDIR}/no-extra-opcode-budget.stx")

if [[ $(echo "$RES" | jq '."txn-groups" | any(has("failure-message"))') != $CONST_TRUE ]]; then
    date '+app-simulate-test FAIL the app call to generated large TEAL without extra budget should fail %Y%m%d_%H%M%S'
    false
fi

EXPECTED_FAILURE='dynamic cost budget exceeded'

if [[ $(echo "$RES" | jq '."txn-groups"[0]."failure-message"') != *"${EXPECTED_FAILURE}"* ]]; then
    date '+app-simulate-test FAIL the app call to generated large TEAL should fail %Y%m%d_%H%M%S'
    false
fi

# SIMULATION! with extra budget should pass direct call
RES=$(${gcmd} clerk simulate --extra-opcode-budget 200 -t "${TEMPDIR}/no-extra-opcode-budget.stx")

if [[ $(echo "$RES" | jq '."txn-groups" | any(has("failure-message"))') != $CONST_FALSE ]]; then
    date '+app-simulate-test FAIL the app call to generated large TEAL with extra budget should pass %Y%m%d_%H%M%S'
    false
fi

if [[ $(echo "$RES" | jq '."eval-overrides"."extra-opcode-budget"') -ne 200 ]]; then
    date '+app-simulate-test FAIL the app call to generated large TEAL should have extra-opcode-budget 200 %Y%m%d_%H%M%S'
    false
fi

if [[ $(echo "$RES" | jq '."txn-groups"[0]."app-budget-added"') -ne 900 ]]; then
    date '+app-simulate-test FAIL the app call to generated large TEAL should have app-budget-added 900 %Y%m%d_%H%M%S'
    false
fi

if [[ $(echo "$RES" | jq '."txn-groups"[0]."app-budget-consumed"') -ne 804 ]]; then
    date '+app-simulate-test FAIL the app call to generated large TEAL should be consuming 804 budget %Y%m%d_%H%M%S'
    false
fi

# SIMULATION! with --allow-more-opcode-budget should pass direct call
RES=$(${gcmd} clerk simulate --allow-more-opcode-budget -t "${TEMPDIR}/no-extra-opcode-budget.stx")

if [[ $(echo "$RES" | jq '."txn-groups" | any(has("failure-message"))') != $CONST_FALSE ]]; then
    date '+app-simulate-test FAIL the app call to generated large TEAL with extra budget should pass %Y%m%d_%H%M%S'
    false
fi

if [[ $(echo "$RES" | jq '."eval-overrides"."extra-opcode-budget"') -ne 320000 ]]; then
    date '+app-simulate-test FAIL the app call to generated large TEAL should have extra-opcode-budget 320000 %Y%m%d_%H%M%S'
    false
fi

if [[ $(echo "$RES" | jq '."txn-groups"[0]."app-budget-added"') -ne 320700 ]]; then
    date '+app-simulate-test FAIL the app call to generated large TEAL should have app-budget-added 320700 %Y%m%d_%H%M%S'
    false
fi

if [[ $(echo "$RES" | jq '."txn-groups"[0]."app-budget-consumed"') -ne 804 ]]; then
    date '+app-simulate-test FAIL the app call to generated large TEAL should be consuming 804 budget %Y%m%d_%H%M%S'
    false
fi

###############################################################
# WE WANT TO TEST STACK AND SCRATCH TRACE IN SIMULATION WORKS #
###############################################################

RES=$(${gcmd} app create --creator ${ACCOUNT} --approval-prog "${DIR}/tealprogs/stack-scratch.teal" --clear-prog "${TEMPDIR}/simple-v8.teal" --extra-pages 1 2>&1 || true)

EXPSUCCESS='Created app with app index'
if [[ $RES != *"${EXPSUCCESS}"* ]]; then
    date '+app-simulate-test FAIL the app creation for generated large TEAL should succeed %Y%m%d_%H%M%S'
    false
fi

APPID=$(echo "$RES" | grep Created | awk '{ print $6 }')

${gcmd} app call --app-id $APPID --app-arg "int:10" --from $ACCOUNT 2>&1 -o "${TEMPDIR}/stack-and-scratch.tx"
${gcmd} clerk sign -i "${TEMPDIR}/stack-and-scratch.tx" -o "${TEMPDIR}/stack-and-scratch.stx"
RES=$(${gcmd} clerk simulate --full-trace -t "${TEMPDIR}/stack-and-scratch.stx")

if [[ $(echo "$RES" | jq '."txn-groups" | any(has("failure-message"))') != $CONST_FALSE ]]; then
    date '+app-simulate-test FAIL the app call for stack and scratch trace should pass %Y%m%d_%H%M%S'
    false
fi

SCRATCH_STORE_UNIT=$(echo "$RES" | jq '."txn-groups"[0]."txn-results"[0]."exec-trace"."approval-program-trace"[-7]')

if [[ $(echo "$SCRATCH_STORE_UNIT" | jq 'has("scratch-changes")') != $CONST_TRUE ]]; then
    data '+app-simulate-test FAIL the app call for stack and scratch trace should return scratch changes at this unit %Y%m%d_%H%M%S'
    false
fi

if [[ $(echo "$SCRATCH_STORE_UNIT" | jq '."scratch-changes" | length') != 1 ]]; then
    data '+app-simulate-test FAIL the app call for stack and scratch trace should return scratch changes with length 1 at this unit %Y%m%d_%H%M%S'
    false
fi

if [[ $(echo "$SCRATCH_STORE_UNIT" | jq 'has("stack-pop-count")') != $CONST_TRUE ]]; then
    data '+app-simulate-test FAIL the app call for stack and scratch trace should return stack pop count at this unit %Y%m%d_%H%M%S'
    false
fi

if [[ $(echo "$SCRATCH_STORE_UNIT" | jq '."stack-pop-count"') != 1 ]]; then
    data '+app-simulate-test FAIL the app call for stack and scratch trace should return stack pop count being 1 at this unit %Y%m%d_%H%M%S'
    false
fi

# WE DON'T TEST IN DETAILS ABOUT SCRATCH AND TRACE IN E2E SCRIPT TESTS, SEE RESTCLIENT TEST FOR DETAILS

##############################################
# TEST ALLOW UNNAMED RESOURCES IN SIMULATION #
##############################################

printf '#pragma version 9\nint 1' > "${TEMPDIR}/simple-v9.teal"

RES=$(${gcmd} app create --creator ${ACCOUNT} --approval-prog "${DIR}/tealprogs/unnamed-resource-access.teal" --clear-prog "${TEMPDIR}/simple-v9.teal" 2>&1 || true)
EXPSUCCESS='Created app with app index'
if [[ $RES != *"${EXPSUCCESS}"* ]]; then
    date '+app-simulate-test FAIL the app creation for unnamed resource access should succeed %Y%m%d_%H%M%S'
    false
fi

OTHERAPPID=$APPID
APPID=$(echo "$RES" | grep Created | awk '{ print $6 }')
APPADDR=$(${gcmd} app info --app-id $APPID | grep "Application account" | awk '{ print $3 }')

${gcmd} clerk send --from $ACCOUNT --to $APPADDR --amount 200000

OTHERADDR=$(${gcmd} app info --app-id $OTHERAPPID | grep "Application account" | awk '{ print $3 }')
${gcmd} clerk send --from $ACCOUNT --to $OTHERADDR --amount 100000

ASSETID=$(${gcmd} asset create --creator ${ACCOUNT} --total 100 | grep Created | awk '{ print $6 }')

# Simulation with default settings should fail
${gcmd} app call --app-id $APPID --from $ACCOUNT --app-arg "addr:$OTHERADDR" --app-arg "int:$ASSETID" --app-arg "int:$OTHERAPPID" 2>&1 -o "${TEMPDIR}/unnamed-resource-access.tx"
${gcmd} clerk sign -i "${TEMPDIR}/unnamed-resource-access.tx" -o "${TEMPDIR}/unnamed-resource-access.stx"
RES=$(${gcmd} clerk simulate -t "${TEMPDIR}/unnamed-resource-access.stx")

if [[ $(echo "$RES" | jq '."txn-groups" | any(has("failure-message"))') != $CONST_TRUE ]]; then
    date '+app-simulate-test FAIL the app call without allow unnamed resources should fail %Y%m%d_%H%M%S'
    false
fi

EXPECTED_FAILURE="logic eval error: unavailable Account $OTHERADDR"

if [[ $(echo "$RES" | jq '."txn-groups"[0]."failure-message"') != *"${EXPECTED_FAILURE}"* ]]; then
    date '+app-simulate-test FAIL the app call without allow unnamed resources should fail with the expected error %Y%m%d_%H%M%S'
    false
fi

# Simulation with --allow-unnamed-resources should succeed
RES=$(${gcmd} clerk simulate --allow-unnamed-resources -t "${TEMPDIR}/unnamed-resource-access.stx")

if [[ $(echo "$RES" | jq '."txn-groups" | any(has("failure-message"))') != $CONST_FALSE ]]; then
    date '+app-simulate-test FAIL the app call with allow unnamed resources should pass %Y%m%d_%H%M%S'
    false
fi

if [[ $(echo "$RES" | jq '."eval-overrides"."allow-unnamed-resources"') != $CONST_TRUE ]]; then
    date '+app-simulate-test FAIL the app call with allow unnamed resources have the correct eval-overrides %Y%m%d_%H%M%S'
    false
fi
