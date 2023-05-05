#!/bin/bash

date '+app-abi-method-test start %Y%m%d_%H%M%S'

set -e
set -x
set -o pipefail
export SHELLOPTS

WALLET=$1

# Directory of this bash program
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

gcmd="goal -w ${WALLET}"

ACCOUNT=$(${gcmd} account list|awk '{ print $3 }')

printf '#pragma version 2\nint 1' > "${TEMPDIR}/simple-v2.teal"
printf '#pragma version 3\nint 1' > "${TEMPDIR}/simple-v3.teal"

# Create
RES=$(${gcmd} app method --method "create(uint64)uint64" --arg "1234" --create --approval-prog ${DIR}/tealprogs/app-abi-method-example.teal --clear-prog ${TEMPDIR}/simple-v2.teal --local-byteslices 1 --from $ACCOUNT 2>&1 || true)
EXPECTED="method create(uint64)uint64 succeeded with output: 2468"
if [[ $RES != *"${EXPECTED}"* ]]; then
    date '+app-abi-method-test FAIL the method call to create(uint64)uint64 should not fail %Y%m%d_%H%M%S'
    false
fi

APPID=$(echo "$RES" | grep Created | awk '{ print $6 }')

# Opt in
RES=$(${gcmd} app method --method "optIn(string)string" --arg "\"Algorand Fan\"" --on-completion optin --app-id $APPID --from $ACCOUNT 2>&1 || true)
EXPECTED="method optIn(string)string succeeded with output: \"hello Algorand Fan\""
if [[ $RES != *"${EXPECTED}"* ]]; then
    date '+app-abi-method-test FAIL the method call to optIn(string)string should not fail %Y%m%d_%H%M%S'
    false
fi

# No arguments or return value
RES=$(${gcmd} app method --method "empty()void" --app-id $APPID --from $ACCOUNT 2>&1 || true)
EXPECTED="method empty()void succeeded"
if [[ $RES != *"${EXPECTED}" ]]; then
    date '+app-abi-method-test FAIL the method call to empty()void should not fail %Y%m%d_%H%M%S'
    false
fi

# 1 + 2 = 3
RES=$(${gcmd} app method --method "add(uint64,uint64)uint64" --arg 1 --arg 2 --app-id $APPID --from $ACCOUNT 2>&1 || true)
EXPECTED="method add(uint64,uint64)uint64 succeeded with output: 3"
if [[ $RES != *"${EXPECTED}"* ]]; then
    date '+app-abi-method-test FAIL the method call to add(uint64,uint64)uint64 should not fail %Y%m%d_%H%M%S'
    false
fi

# 18446744073709551614 + 1 = 18446744073709551615
RES=$(${gcmd} app method --method "add(uint64,uint64)uint64" --arg 18446744073709551614 --arg 1 --app-id $APPID --from $ACCOUNT 2>&1 || true)
EXPECTED="method add(uint64,uint64)uint64 succeeded with output: 18446744073709551615"
if [[ $RES != *"${EXPECTED}"* ]]; then
    date '+app-abi-method-test FAIL the method call to add(uint64,uint64)uint64 should not fail %Y%m%d_%H%M%S'
    false
fi

goal clerk send --from $ACCOUNT --to $ACCOUNT --amount 1000000 -o "${TEMPDIR}/pay-txn-arg.tx"

# Payment with return true
RES=$(${gcmd} app method --method "payment(pay,uint64)bool" --arg ${TEMPDIR}/pay-txn-arg.tx --arg 1000000 --app-id $APPID --from $ACCOUNT 2>&1 || true)
EXPECTED="method payment(pay,uint64)bool succeeded with output: true"
if [[ $RES != *"${EXPECTED}"* ]]; then
    date '+app-abi-method-test FAIL the method call to payment(pay,uint64)bool should not fail %Y%m%d_%H%M%S'
    false
fi

# Payment with return false
RES=$(${gcmd} app method --method "payment(pay,uint64)bool" --arg ${TEMPDIR}/pay-txn-arg.tx --arg 1000001 --app-id $APPID --from $ACCOUNT 2>&1 || true)
EXPECTED="method payment(pay,uint64)bool succeeded with output: false"
if [[ $RES != *"${EXPECTED}"* ]]; then
    date '+app-abi-method-test FAIL the method call to payment(pay,uint64)bool should not fail %Y%m%d_%H%M%S'
    false
fi

# Foreign reference test during non-creation call. A creation test is further down.
RES=$(${gcmd} app method --method "referenceTest(account,application,account,asset,account,asset,asset,application,application)uint8[9]" --arg KGTOR3F3Q74JP4LB5M3SOCSJ4BOPOKZ2GPSLMLLGCWYWRXZJNN4LYQJXXU --arg $APPID --arg $ACCOUNT --arg 10 --arg KGTOR3F3Q74JP4LB5M3SOCSJ4BOPOKZ2GPSLMLLGCWYWRXZJNN4LYQJXXU --arg 11 --arg 10 --arg 20 --arg 21 --app-account 2R5LMPTYLVMWYEG4RPI26PJAM7ARTGUB7LZSONQPGLUWTPOP6LQCJTQZVE --foreign-app 21 --foreign-asset 10 --app-id $APPID --from $ACCOUNT 2>&1 || true)
EXPECTED="method referenceTest(account,application,account,asset,account,asset,asset,application,application)uint8[9] succeeded with output: [2,0,2,0,2,1,0,1,0]"
if [[ $RES != *"${EXPECTED}"* ]]; then
    date '+app-abi-method-test FAIL the method call to referenceTest(account,application,account,asset,account,asset,asset,application,application)uint8[9] should not fail %Y%m%d_%H%M%S'
    false
fi

# Close out
RES=$(${gcmd} app method --method "closeOut()string" --on-completion closeout --app-id $APPID --from $ACCOUNT 2>&1 || true)
EXPECTED="method closeOut()string succeeded with output: \"goodbye Algorand Fan\""
if [[ $RES != *"${EXPECTED}"* ]]; then
    date '+app-abi-method-test FAIL the method call to closeOut()string should not fail %Y%m%d_%H%M%S'
    false
fi

# Update
RES=$(${gcmd} app method --method "update()void" --on-completion updateapplication --approval-prog ${DIR}/tealprogs/app-abi-method-example.teal --clear-prog ${TEMPDIR}/simple-v3.teal --app-id $APPID --from $ACCOUNT 2>&1 || true)
EXPECTED="method update()void succeeded"
if [[ $RES != *"${EXPECTED}"* ]]; then
    date '+app-abi-method-test FAIL the method call to update()void should not fail %Y%m%d_%H%M%S'
    false
fi

# Delete
RES=$(${gcmd} app method --method "delete()void" --on-completion deleteapplication --app-id $APPID --from $ACCOUNT 2>&1 || true)
EXPECTED="method delete()void succeeded"
if [[ $RES != *"${EXPECTED}"* ]]; then
    date '+app-abi-method-test FAIL the method call to delete()void should not fail %Y%m%d_%H%M%S'
    false
fi

# Foreign reference test during creation
RES=$(${gcmd} app method --create --approval-prog ${DIR}/tealprogs/app-abi-method-example.teal --clear-prog ${TEMPDIR}/simple-v2.teal --local-byteslices 1 --on-completion deleteapplication --method "referenceTest(account,application,account,asset,account,asset,asset,application,application)uint8[9]" --arg KGTOR3F3Q74JP4LB5M3SOCSJ4BOPOKZ2GPSLMLLGCWYWRXZJNN4LYQJXXU --arg 0 --arg $ACCOUNT --arg 10 --arg KGTOR3F3Q74JP4LB5M3SOCSJ4BOPOKZ2GPSLMLLGCWYWRXZJNN4LYQJXXU --arg 11 --arg 10 --arg 20 --arg 21 --app-account 2R5LMPTYLVMWYEG4RPI26PJAM7ARTGUB7LZSONQPGLUWTPOP6LQCJTQZVE --foreign-app 21 --foreign-asset 10 --from $ACCOUNT 2>&1 || true)
EXPECTED="method referenceTest(account,application,account,asset,account,asset,asset,application,application)uint8[9] succeeded with output: [2,0,2,0,2,1,0,1,0]"
if [[ $RES != *"${EXPECTED}"* ]]; then
    date '+app-abi-method-test FAIL the creation method call to referenceTest(account,application,account,asset,account,asset,asset,application,application)uint8[9] should not fail %Y%m%d_%H%M%S'
    false
fi
