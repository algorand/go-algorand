#!/bin/bash

date '+app-simple-test start %Y%m%d_%H%M%S'

set -e
set -x
set -o pipefail
set -o nounset
export SHELLOPTS

WALLET=$1

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