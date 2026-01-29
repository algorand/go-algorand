#!/bin/bash

date '+e2e_teal start %Y%m%d_%H%M%S'

set -e
set -x
set -o pipefail
export SHELLOPTS

WALLET=$1

gcmd="goal -w ${WALLET}"

TEAL=test/scripts/e2e_subs/tealprogs

ACCOUNT=$(${gcmd} account list|awk '{ print $3 }')

# prints:
# Created new account with address UCTHHNBEAUWHDQWQI5DGQCTB7AR4CSVNU5YNPROAYQIT3Y3LKVDFAA5M6Q
ACCOUNTB=$(${gcmd} account new|awk '{ print $6 }')

ROUND=$(goal node status | grep 'Last committed block:'|awk '{ print $4 }')
TIMEOUT_ROUND=$((${ROUND} + 14))

# timeout after 14 rounds
python data/transactions/logic/tlhc.py --from ${ACCOUNT} --to ${ACCOUNTB} --timeout-round ${TIMEOUT_ROUND} > ${TEMPDIR}/tlhc.teal 2> ${TEMPDIR}/tlhc.teal.secret

cat ${TEMPDIR}/tlhc.teal

ACCOUNT_TLHC=$(${gcmd} clerk compile -n ${TEMPDIR}/tlhc.teal|awk '{ print $2 }')

${gcmd} clerk send --amount 1000000 --from ${ACCOUNT} --to ${ACCOUNT_TLHC}

set +e

# this will be rejected until after the round is late
${gcmd} clerk send --from-program ${TEMPDIR}/tlhc.teal --to ${ACCOUNT} --close-to ${ACCOUNT} --amount 1 --argb64 AA==
if [ $? -eq 0 ]; then
    echo "early refund should have failed"
    exit 1
fi

TLHC_SECRET=$(awk '{ print $4 }'<${TEMPDIR}/tlhc.teal.secret)

# this will be rejected until after the timeout round
${gcmd} clerk send --from-program ${TEMPDIR}/tlhc.teal --to ${ACCOUNT} --close-to ${ACCOUNT} --amount 1 --argb64 ${TLHC_SECRET}
if [ $? -eq 0 ]; then
    echo "early refund with secret should have failed"
    exit 1
fi

set -e
# this should pass
${gcmd} clerk send --from-program ${TEMPDIR}/tlhc.teal --to ${ACCOUNTB} --close-to ${ACCOUNTB} --amount 1 --argb64 ${TLHC_SECRET}
set +e

# but it should fail the second time because the money was spent
${gcmd} clerk send --from-program ${TEMPDIR}/tlhc.teal --to ${ACCOUNTB} --close-to ${ACCOUNTB} --amount 1 --argb64 ${TLHC_SECRET}
if [ $? -eq 0 ]; then
    echo "empty spend should have failed"
    exit 1
fi

set -e
${gcmd} clerk send --amount 1000000 --from ${ACCOUNT} --to ${ACCOUNT_TLHC}

# timeout round should pass. some of the 35 seconds was eaten by prior ops.
CROUND=$(goal node status | grep 'Last committed block:'|awk '{ print $4 }')
while [ $CROUND -lt $TIMEOUT_ROUND ]; do
    goal node wait --waittime 30
    CROUND=$(goal node status | grep 'Last committed block:'|awk '{ print $4 }')
done

# send txn that valid right after the TIMEOUT_ROUND
${gcmd} clerk send --firstvalid $((${TIMEOUT_ROUND} + 1))  --from-program ${TEMPDIR}/tlhc.teal --to ${ACCOUNT} --close-to ${ACCOUNT} --amount 1 --argb64 AA==

cat >${TEMPDIR}/true.teal<<EOF
#pragma version 2
int 1
EOF

${gcmd} clerk compile -o ${TEMPDIR}/true.lsig -s -a ${ACCOUNT} ${TEMPDIR}/true.teal

${gcmd} clerk send -f ${ACCOUNT} -t ${ACCOUNTB} -a 1000000 -L ${TEMPDIR}/true.lsig

${gcmd} clerk send -f ${ACCOUNT} -t ${ACCOUNTB} -a 1000000 -o ${TEMPDIR}/one.tx

${gcmd} clerk sign -L ${TEMPDIR}/true.lsig -i ${TEMPDIR}/one.tx -o ${TEMPDIR}/one.stx

${gcmd} clerk rawsend -f ${TEMPDIR}/one.stx

${gcmd} clerk dryrun -t ${TEMPDIR}/one.stx

ACCOUNT_TRUE=$(${gcmd} clerk compile -n ${TEMPDIR}/true.teal|awk '{ print $2 }')

${gcmd} clerk send --amount 1000000 --from ${ACCOUNT} --to ${ACCOUNT_TRUE}

${gcmd} clerk send --amount 10 --from-program ${TEMPDIR}/true.teal --to ${ACCOUNTB}

${gcmd} clerk send --amount 10 --from ${ACCOUNT_TRUE} --to ${ACCOUNTB} -o ${TEMPDIR}/true.tx

${gcmd} clerk sign -i ${TEMPDIR}/true.tx -o ${TEMPDIR}/true.stx --program ${TEMPDIR}/true.teal

${gcmd} clerk rawsend -f ${TEMPDIR}/true.stx

${gcmd} clerk inspect ${TEMPDIR}/true.stx

${gcmd} clerk compile -D ${TEMPDIR}/true.lsig

ACCOUNTC=$(${gcmd} account new|awk '{ print $6 }')

ACCOUNTM=$(${gcmd} account multisig new -T 2 ${ACCOUNT} ${ACCOUNTB} ${ACCOUNTC}|awk '{ print $6 }')


${gcmd} clerk multisig signprogram -p ${TEMPDIR}/true.teal -a ${ACCOUNT} -A ${ACCOUNTM} -o ${TEMPDIR}/mtrue.lsig

${gcmd} clerk multisig signprogram -L ${TEMPDIR}/mtrue.lsig -a ${ACCOUNTC}

${gcmd} clerk send --amount 1000000 --from ${ACCOUNT} --to ${ACCOUNTM}

${gcmd} clerk send --amount 200000 --from ${ACCOUNTM} --to ${ACCOUNTC} -L ${TEMPDIR}/mtrue.lsig

# Test new multisig mode (e2e using vFuture)
echo "Testing multisig mode..."
${gcmd} clerk multisig signprogram --legacy-msig=false -p ${TEMPDIR}/true.teal -a ${ACCOUNT} -A ${ACCOUNTM} -o ${TEMPDIR}/mtrue_new.lsig
${gcmd} clerk multisig signprogram --legacy-msig=false -L ${TEMPDIR}/mtrue_new.lsig -a ${ACCOUNTB} -o ${TEMPDIR}/mtrue_new2.lsig
${gcmd} clerk send --amount 100000 --from ${ACCOUNTM} --to ${ACCOUNTB} -L ${TEMPDIR}/mtrue_new2.lsig

# Test that mixing modes fails: since this is vFuture, mtrue.lsig has LMsig field
# Try to use it with --legacy-msig=true (which expects Msig field)
set +e
OUTPUT=$(${gcmd} clerk multisig signprogram --legacy-msig=true -L ${TEMPDIR}/mtrue.lsig -a ${ACCOUNTB} -o ${TEMPDIR}/mtrue_mixed.lsig 2>&1)
if [ $? -eq 0 ]; then
    echo "ERROR: Expected failure when mixing new signature with legacy mode, but command succeeded"
    exit 1
fi
echo "$OUTPUT" | grep -q "LogicSig file contains LMsig field"
if [ $? -ne 0 ]; then
    echo "ERROR: Expected error message about LMsig field, got: $OUTPUT"
    exit 1
fi
echo "Correctly rejected mixing new signature with legacy mode"
set -e

echo "#pragma version 1" | ${gcmd} clerk compile -
echo "#pragma version 2" | ${gcmd} clerk compile -

set +o pipefail
# The compile will fail, but this tests against a regression in which compile SEGV'd
echo "#pragma version 100" | ${gcmd} clerk compile - 2>&1 | grep "unsupported version"
set -o pipefail


# Compile a v3 version of same program, fund it, use it to lsig.
cat >${TEMPDIR}/true3.teal<<EOF
#pragma version 3
int 1
assert
int 1
EOF

ACCOUNT_TRUE=$(${gcmd} clerk compile -n ${TEMPDIR}/true3.teal|awk '{ print $2 }')
${gcmd} clerk send --amount 1000000 --from ${ACCOUNT} --to ${ACCOUNT_TRUE}
${gcmd} clerk send --amount 10 --from-program ${TEMPDIR}/true3.teal --to ${ACCOUNTB}


# However, ensure it fails if marked v2.  We have to be tricky here,
# since the compiler won't let us compile this, we rewrite the first
# byte to 2, then compute the new account, and try use.  But since it
# uses assert in a v2 program, it fails.

${gcmd} clerk compile ${TEMPDIR}/true3.teal -o ${TEMPDIR}/true3.lsig
cp ${TEMPDIR}/true3.lsig ${TEMPDIR}/true2.lsig
printf '\x02' | dd of=${TEMPDIR}/true2.lsig bs=1 seek=0 count=1 conv=notrunc

# Try to compile with source map, and check that map is correct.
# Since the source map contains info about the file path,
# we do this in place and clean up the file later.
${gcmd} clerk compile ${TEAL}/quine.teal -m
trap 'rm ${TEAL}/quine.teal.*' EXIT
if ! diff ${TEAL}/quine.map ${TEAL}/quine.teal.tok.map; then
    echo "produced source maps do not match: ${TEAL}/quine.map vs ${TEAL}/quine.teal.tok.map"
    exit 1
fi

${gcmd} clerk compile ${TEAL}/sourcemap-test.teal -m
trap 'rm ${TEAL}/sourcemap-test.teal.*' EXIT
if ! diff ${TEAL}/sourcemap-test.map ${TEAL}/sourcemap-test.teal.tok.map; then
    echo "produced source maps do not match: ${TEAL}/sourcemap-test.map vs ${TEAL}/sourcemap-test.teal.tok.map"
    exit 1
fi

# compute the escrow account for the frankenstein program
ACCOUNT_TRUE=$(python -c 'import algosdk, sys; print(algosdk.logic.address(sys.stdin.buffer.read()))' < ${TEMPDIR}/true2.lsig)
# fund that escrow account
${gcmd} clerk send --amount 1000000 --from ${ACCOUNT} --to ${ACCOUNT_TRUE}
# try, and fail, to lsig with it
set +o pipefail
${gcmd} clerk send --amount 10 --from-program-bytes ${TEMPDIR}/true2.lsig --to ${ACCOUNTB} 2>&1 | grep "illegal opcode"
set -o pipefail


date '+e2e_teal OK %Y%m%d_%H%M%S'
