#!/bin/bash

filename=$(basename "$0")
scriptname="${filename%.*}"
date "+${scriptname} start %Y%m%d_%H%M%S"

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

# Fair number of temporary files, just cd into TEMPDIR first
cd ${TEMPDIR}

# Test 1: Explicit tip only (fee should be calculated from tip)
${gcmd} clerk send -a 100 -f "${ACCOUNT}" -t "${ACCOUNT}" --tip 100000 -o tip-only.txn
TIP_ONLY=$(msgpacktool -d < tip-only.txn)
# Tip should be 100000 (0.1 = 10%)
echo "$TIP_ONLY" | grep '"tp"' | grep 100000
# Fee should be minFee * (1 + 0.1) = minFee * 1.1
EXPECTED_FEE=$((MIN_FEE * 11 / 10))
echo "$TIP_ONLY" | grep '"fee"' | grep ${EXPECTED_FEE}

# Test 2: Explicit fee and tip
${gcmd} clerk send -a 100 -f "${ACCOUNT}" -t "${ACCOUNT}" --fee 2000 --tip 50000 -o both.txn
BOTH=$(msgpacktool -d < both.txn)
echo "$BOTH" | grep '"fee"' | grep 2000
echo "$BOTH" | grep '"tp"' | grep 50000

# Test 3: Explicit fee only (tip should be zero because we don't
# expect congestion in e2e tests, not encoded due to omitempty)
${gcmd} clerk send -a 100 -f "${ACCOUNT}" -t "${ACCOUNT}" --fee 1500 -o fee-only.txn
FEE_ONLY=$(msgpacktool -d < fee-only.txn)
echo "$FEE_ONLY" | grep '"fee"' | grep 1500
# Tip should not be encoded when zero (omitempty)
set +e
FOUND=$(echo "$FEE_ONLY" | grep '"tp"')
set -e
if [[ $FOUND != "" ]]; then
    date "+${scriptname} FAIL tip was improperly encoded when only fee set: $FOUND %Y%m%d_%H%M%S"
    false
fi

# Test 4: Neither fee nor tip set (should get suggested fee and tip from network)
${gcmd} clerk send -a 100 -f "${ACCOUNT}" -t "${ACCOUNT}" -o suggested.txn
SUGGESTED=$(msgpacktool -d < suggested.txn)
# Fee should be present
echo "$SUGGESTED" | grep '"fee"'
# Tip should not be encoded when zero (omitempty) since e2e tests have no congestion
set +e
FOUND=$(echo "$SUGGESTED" | grep '"tp"')
set -e
if [[ $FOUND != "" ]]; then
    date "+${scriptname} FAIL tip was improperly present by default: $FOUND %Y%m%d_%H%M%S"
    false
fi

# Test 5: Zero fee explicitly set (for use in transaction groups)
${gcmd} clerk send -a 100 -f "${ACCOUNT}" -t "${ACCOUNT}" --fee 0 -o zero-fee.txn
ZERO_FEE=$(msgpacktool -d < zero-fee.txn)
# Fee should not be encoded when zero (omitempty)
set +e
FOUND=$(echo "$ZERO_FEE" | grep '"fee"')
set -e
if [[ $FOUND != "" ]]; then
    date "+${scriptname} FAIL fee was improperly encoded when set to zero: $FOUND %Y%m%d_%H%M%S"
    false
fi

date "+${scriptname} OK %Y%m%d_%H%M%S"
