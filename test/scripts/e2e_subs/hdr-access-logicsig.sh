#!/bin/bash

filename=$(basename "$0")
scriptname="${filename%.*}"
date "+${scriptname} start %Y%m%d_%H%M%S"

set -e
set -x
set -o pipefail

WALLET=$1

gcmd="goal -w ${WALLET}"

ACCOUNT=$(${gcmd} account list|awk '{ print $3 }')

cat >${TEMPDIR}/hdr.teal<<EOF
#pragma version 7
txn FirstValid
int 1
-
block BlkTimestamp // need to make sure we don't ask for current

txn FirstValid
int 2
-
block BlkTimestamp
// last two times are on stack
-
dup
// difference in times is on stack twice

int 1
>
assert

int 6
<
EOF

${gcmd} clerk compile -o ${TEMPDIR}/hdr.lsig -s -a ${ACCOUNT} ${TEMPDIR}/hdr.teal

ACCOUNT_HDR=$(${gcmd} clerk compile -n ${TEMPDIR}/hdr.teal|awk '{ print $2 }')

${gcmd} clerk send --amount 1000000 --from ${ACCOUNT} --to ${ACCOUNT_HDR}

# Don't let goal set lastvalid so far in the future, that prevents `block` access
${gcmd} clerk send --amount 10 --from ${ACCOUNT_HDR} --to ${ACCOUNT} --lastvalid 100 -o ${TEMPDIR}/hdr.tx

${gcmd} clerk sign -i ${TEMPDIR}/hdr.tx -o ${TEMPDIR}/hdr.stx --program ${TEMPDIR}/hdr.teal

${gcmd} clerk rawsend -f ${TEMPDIR}/hdr.stx

${gcmd} clerk inspect ${TEMPDIR}/hdr.stx
