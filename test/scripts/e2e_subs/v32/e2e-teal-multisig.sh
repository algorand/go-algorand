#!/bin/bash

# Test multisig logic signatures on old algod (v32 consensus)
# v32 consensus should have LogicSigMsig=true, LogicSigLMsig=false (legacy mode only)

date '+e2e_teal_multisig_v32 start %Y%m%d_%H%M%S'

set -e
set -x
set -o pipefail
export SHELLOPTS

WALLET=$1

gcmd="goal -w ${WALLET}"

# Create test accounts
ACCOUNT_A=$(${gcmd} account list|awk '{ print $3 }')
ACCOUNT_B=$(${gcmd} account new|awk '{ print $6 }')
ACCOUNT_C=$(${gcmd} account new|awk '{ print $6 }')

# Create a 2-of-3 multisig account
ACCOUNT_MSIG=$(${gcmd} account multisig new -T 2 ${ACCOUNT_A} ${ACCOUNT_B} ${ACCOUNT_C}|awk '{ print $6 }')

# Create a simple always-true program
cat >${TEMPDIR}/msig_true.teal<<EOF
#pragma version 2
int 1
EOF

# Fund the multisig account
${gcmd} clerk send --amount 10000000 --from ${ACCOUNT_A} --to ${ACCOUNT_MSIG}

# Legacy mode (--legacy-msig=true) should work on v32
${gcmd} clerk multisig signprogram --legacy-msig=true -p ${TEMPDIR}/msig_true.teal -a ${ACCOUNT_A} -A ${ACCOUNT_MSIG} -o ${TEMPDIR}/legacy1.lsig
${gcmd} clerk multisig signprogram --legacy-msig=true -L ${TEMPDIR}/legacy1.lsig -a ${ACCOUNT_B} -o ${TEMPDIR}/legacy2.lsig
${gcmd} clerk send --amount 100000 --from ${ACCOUNT_MSIG} --to ${ACCOUNT_A} -L ${TEMPDIR}/legacy2.lsig
if [ $? -ne 0 ]; then
    echo "ERROR: Legacy mode transaction failed on v32"
    exit 1
fi
echo "Legacy mode transaction succeeded on v32"

# New mode (--legacy-msig=false) should fail on v32
${gcmd} clerk multisig signprogram --legacy-msig=false -p ${TEMPDIR}/msig_true.teal -a ${ACCOUNT_A} -A ${ACCOUNT_MSIG} -o ${TEMPDIR}/new1.lsig
${gcmd} clerk multisig signprogram --legacy-msig=false -L ${TEMPDIR}/new1.lsig -a ${ACCOUNT_B} -o ${TEMPDIR}/new2.lsig
set +e
${gcmd} clerk send --amount 100000 --from ${ACCOUNT_MSIG} --to ${ACCOUNT_A} -L ${TEMPDIR}/new2.lsig 2>&1 | tee ${TEMPDIR}/new_send.out
SEND_RESULT=$?
set -e

if [ $SEND_RESULT -eq 0 ] || ! grep -q "LMsig field not supported" ${TEMPDIR}/new_send.out; then
    echo "ERROR: Expected failure with 'LMsig field not supported' error but got:"
    cat ${TEMPDIR}/new_send.out
    exit 1
fi
echo "New mode transaction rejected on v32"

# Auto-detection should use legacy mode on v32
${gcmd} clerk multisig signprogram -p ${TEMPDIR}/msig_true.teal -a ${ACCOUNT_A} -A ${ACCOUNT_MSIG} -o ${TEMPDIR}/auto1.lsig
${gcmd} clerk multisig signprogram -L ${TEMPDIR}/auto1.lsig -a ${ACCOUNT_B} -o ${TEMPDIR}/auto2.lsig
${gcmd} clerk send --amount 100000 --from ${ACCOUNT_MSIG} --to ${ACCOUNT_A} -L ${TEMPDIR}/auto2.lsig
if [ $? -ne 0 ]; then
    echo "ERROR: Auto-detection transaction failed on v32"
    exit 1
fi
echo "Auto-detection correctly used legacy mode on v32"
if ! cat ${TEMPDIR}/auto2.lsig | msgpacktool -d | grep -q '"msig"'; then
    echo "ERROR: Auto-detection did not use legacy mode (Msig field not found)"
    exit 1
fi
echo "Auto-detection used legacy mode (Msig field present)"

# Error cases
set +e
OUTPUT=$(${gcmd} clerk multisig signprogram --legacy-msig=false -L ${TEMPDIR}/legacy1.lsig -a ${ACCOUNT_C} -o ${TEMPDIR}/mixed.lsig 2>&1)
if [ $? -eq 0 ] || ! echo "$OUTPUT" | grep -q "contains Msig field"; then
    echo "ERROR: Expected failure with 'contains Msig field' error but got:"
    echo "$OUTPUT"
    exit 1
fi
echo "Correctly rejected mixing legacy signature with new mode"

OUTPUT2=$(${gcmd} clerk multisig signprogram --legacy-msig=true -L ${TEMPDIR}/new1.lsig -a ${ACCOUNT_C} -o ${TEMPDIR}/mixed2.lsig 2>&1)
if [ $? -eq 0 ] || ! echo "$OUTPUT2" | grep -q "contains LMsig field"; then
    echo "ERROR: Expected failure with 'contains LMsig field' error but got:"
    echo "$OUTPUT2"
    exit 1
fi
echo "Correctly rejected mixing new signature with legacy mode"
set -e

# When algod is offline, auto-detection should use new mode
goal node stop
sleep 2

# Try auto-detection while offline - should fail and default to new mode (LMsig)
set +e
${gcmd} clerk multisig signprogram -p ${TEMPDIR}/msig_true.teal -a ${ACCOUNT_A} -A ${ACCOUNT_MSIG} -o ${TEMPDIR}/offline_auto.lsig 2>&1 | tee ${TEMPDIR}/offline_test.out
OFFLINE_RESULT=$?
if [ $OFFLINE_RESULT -ne 0 ]; then
    echo "ERROR: Failed to create signature while algod offline"
    exit 1
fi
echo "Created signature while algod offline"

# Use msgpacktool to verify which field was used
if msgpacktool -d < ${TEMPDIR}/offline_auto.lsig | grep -q '"lmsig"'; then
    echo "Auto-detection defaulted to new mode (LMsig) when offline"
elif msgpacktool -d < ${TEMPDIR}/offline_auto.lsig | grep -q '"msig"'; then
    echo "ERROR: Auto-detection used legacy mode (Msig) when offline - expected new mode"
    exit 1
else
    echo "ERROR: Unable to determine which field was used in offline signature"
    msgpacktool -d < ${TEMPDIR}/offline_auto.lsig
    exit 1
fi
set -e

date '+e2e_teal_multisig_v32 done %Y%m%d_%H%M%S'
