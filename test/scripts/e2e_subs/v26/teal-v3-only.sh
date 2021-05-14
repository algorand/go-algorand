#!/bin/bash

date '+teal-v3-only start %Y%m%d_%H%M%S'

set -e
set -x
set -o pipefail
export SHELLOPTS

WALLET=$1

gcmd="goal -w ${WALLET}"

ACCOUNT=$(${gcmd} account list|awk '{ print $3 }')

# prints:
# Created new account with address UCTHHNBEAUWHDQWQI5DGQCTB7AR4CSVNU5YNPROAYQIT3Y3LKVDFAA5M6Q
ACCOUNTB=$(${gcmd} account new|awk '{ print $6 }')

cat >${TEMPDIR}/true.teal<<EOF
#pragma version 3
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

echo "#pragma version 1" | ${gcmd} clerk compile -
echo "#pragma version 2" | ${gcmd} clerk compile -
echo "#pragma version 3" | ${gcmd} clerk compile -



set +o pipefail
# v4 opcodes with v3 pragma fails
printf "#pragma version 3\nbegin: int 1\nb begin" | ${gcmd} clerk compile - 2>&1 | grep "back jump support"
set -o pipefail

# Although we are in an earlier version, v4 can be compiled, it just can't be used.
cat >${TEMPDIR}/true4.teal<<EOF
#pragma version 4
int 1
EOF


ACCOUNT_TRUE=$(${gcmd} clerk compile -n ${TEMPDIR}/true4.teal|awk '{ print $2 }')

${gcmd} clerk send --amount 1000000 --from ${ACCOUNT} --to ${ACCOUNT_TRUE}

set +o pipefail
${gcmd} clerk send --amount 10 --from-program ${TEMPDIR}/true4.teal --to ${ACCOUNTB} 2>&1 | grep "LogicSig.Logic version too new"
set -o pipefail


# Now, ensure it still fails, even if using the v3 program, if the
# retsub opcode is added. (That is, failure based on opcode choice,
# not just on the version marker.)

${gcmd} clerk compile ${TEMPDIR}/true.teal -o ${TEMPDIR}/true.lsig
# append "retsub" opcode to the true program (won't execute the opcode, but presence should cause fail)
# we can't assemble this, because it would be rejected
(cat ${TEMPDIR}/true.lsig; printf '\x89') > ${TEMPDIR}/retsub.lsig
# compute the escrow account for the retsub program
ACCOUNT_TRUE=$(python -c 'import algosdk, sys; print(algosdk.logic.address(sys.stdin.buffer.read()))' < ${TEMPDIR}/retsub.lsig)
# fund that escrow account
${gcmd} clerk send --amount 1000000 --from ${ACCOUNT} --to ${ACCOUNT_TRUE}
# try, and fail, to lsig with the retsub program
set +o pipefail
${gcmd} clerk send --amount 10 --from-program-bytes ${TEMPDIR}/retsub.lsig --to ${ACCOUNTB} 2>&1 | grep "illegal opcode"
set -o pipefail



date '+teal-v3-only OK %Y%m%d_%H%M%S'
