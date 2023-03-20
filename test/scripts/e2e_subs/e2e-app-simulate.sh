#!/bin/bash

date '+app-simple-test start %Y%m%d_%H%M%S'

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

${gcmd} clerk send -a 10000 -f ${ACCOUNT} -t ${ACCOUNT} -o pay1.tx
${gcmd} clerk send -a 10000 -f ${ACCOUNT} -t ${ACCOUNT} -o pay2.tx

cat pay1.tx pay2.tx | ${gcmd} clerk group -i - -o grouped.tx
${gcmd} clerk split -i grouped.tx -o grouped.tx

${gcmd} clerk sign -i grouped-0.tx -o grouped-0.stx
${gcmd} clerk sign -i grouped-1.tx -o grouped-1.stx

cat grouped-0.stx grouped-1.stx > grouped.stx

RES=$(${gcmd} clerk simulate -t grouped.stx)
EXPSUCCESS='"would-succeed": true'

if [[ $RES != *"${EXPSUCCESS}"* ]]; then
    date '+app-simulate-test FAIL should pass to simulate self pay transaction group %Y%m%d_%H%M%S'
    false
fi

#######################################################
# NOW WE TRY TO TEST SIMULATION WITH ABI METHOD CALLS #
#######################################################

printf '#pragma version 2\nint 1' > "${TEMPDIR}/simple-v2.teal"
printf '#pragma version 3\nint 1' > "${TEMPDIR}/simple-v3.teal"

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

EXPFAIL='"would-succeed": false'

FAIL_REASON_SIG_MISSING='"missing-signature": true'

# confirm that without signature, the simulation should fail
if [[ $RES != *"${EXPFAIL}"* ]]; then
    date '+app-simulate-test FAIL the simulation call to empty()void without signature should not succeed %Y%m%d_%H%M%S'
    false
fi

# check again the simulation failing reason
if [[ $RES != *"${FAIL_REASON_SIG_MISSING}"* ]]; then
    date '+app-simulate-test FAIL the simulation call to empty()void without signature should fail with missing-signature %Y%m%d_%H%M%S'
    false
fi

# SIMULATE with a signature
${gcmd} clerk sign -i empty.tx -o empty.stx
RES=$(${gcmd} clerk simulate -t empty.stx)

# with signature, simulation app-call should succeed
if [[ $RES != *"${EXPSUCCESS}"* ]]; then
    date '+app-simulate-test FAIL the simulation call to empty()void should succeed %Y%m%d_%H%M%S'
    false
fi
