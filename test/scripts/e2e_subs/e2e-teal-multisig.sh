#!/bin/bash

date '+e2e_teal_multisig_future start %Y%m%d_%H%M%S'

set -e
set -x
set -o pipefail
export SHELLOPTS

WALLET=$1

gcmd="goal -w ${WALLET}"

# Create 2-of-3 multisig
ACCOUNT_A=$(${gcmd} account list|awk '{ print $3 }')
ACCOUNT_B=$(${gcmd} account new|awk '{ print $6 }')
ACCOUNT_C=$(${gcmd} account new|awk '{ print $6 }')
ACCOUNT_MSIG=$(${gcmd} account multisig new -T 2 ${ACCOUNT_A} ${ACCOUNT_B} ${ACCOUNT_C}|awk '{ print $6 }')

cat >${TEMPDIR}/msig_true.teal<<EOF
#pragma version 2
int 1
EOF

${gcmd} clerk send --amount 10000000 --from ${ACCOUNT_A} --to ${ACCOUNT_MSIG}

# Create legacy mode signatures
${gcmd} clerk multisig signprogram --legacy-msig=true -p ${TEMPDIR}/msig_true.teal -a ${ACCOUNT_A} -A ${ACCOUNT_MSIG} -o ${TEMPDIR}/legacy1.lsig
${gcmd} clerk multisig signprogram --legacy-msig=true -L ${TEMPDIR}/legacy1.lsig -a ${ACCOUNT_B} -o ${TEMPDIR}/legacy2.lsig
# Try to use the legacy mode on vFuture
set +e
${gcmd} clerk send --amount 100000 --from ${ACCOUNT_MSIG} --to ${ACCOUNT_A} -L ${TEMPDIR}/legacy2.lsig 2>&1 | tee ${TEMPDIR}/legacy_send.out
SEND_RESULT=$?
set -e

if [ $SEND_RESULT -eq 0 ] || ! grep -q "Msig field not supported" ${TEMPDIR}/legacy_send.out; then
    echo "ERROR: Expected failure with 'Msig field not supported' error but got:"
    cat ${TEMPDIR}/legacy_send.out
    exit 1
fi
echo "Legacy mode transaction rejected on vFuture"

# Sign with new mode explicitly set
${gcmd} clerk multisig signprogram --legacy-msig=false -p ${TEMPDIR}/msig_true.teal -a ${ACCOUNT_A} -A ${ACCOUNT_MSIG} -o ${TEMPDIR}/new1.lsig
${gcmd} clerk multisig signprogram --legacy-msig=false -L ${TEMPDIR}/new1.lsig -a ${ACCOUNT_B} -o ${TEMPDIR}/new2.lsig
# Use the new LMsig on vFuture, should succeed
${gcmd} clerk send --amount 100000 --from ${ACCOUNT_MSIG} --to ${ACCOUNT_A} -L ${TEMPDIR}/new2.lsig
if [ $? -ne 0 ]; then
    echo "ERROR: New mode transaction failed on future consensus"
    exit 1
fi
echo "New mode transaction succeeded on future consensus"

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

# Sign and send without specifying mode - should auto-detect and use new mode on vFuture
${gcmd} clerk multisig signprogram -p ${TEMPDIR}/msig_true.teal -a ${ACCOUNT_A} -A ${ACCOUNT_MSIG} -o ${TEMPDIR}/auto1.lsig
${gcmd} clerk multisig signprogram -L ${TEMPDIR}/auto1.lsig -a ${ACCOUNT_B} -o ${TEMPDIR}/auto2.lsig
${gcmd} clerk send --amount 100000 --from ${ACCOUNT_MSIG} --to ${ACCOUNT_A} -L ${TEMPDIR}/auto2.lsig
echo "Auto-detection correctly used new mode on future consensus"

# Verify auto-detection used new mode (LMsig field)
if ! cat ${TEMPDIR}/auto2.lsig | msgpacktool -d | grep -q '"lmsig"'; then
    echo "ERROR: Auto-detection did not use new mode (LMsig field not found)"
    exit 1
fi
echo "Auto-detection used new mode (LMsig field present)"

date '+e2e_teal_multisig_future done %Y%m%d_%H%M%S'
