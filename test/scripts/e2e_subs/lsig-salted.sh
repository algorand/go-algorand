#!/bin/bash

filename=$(basename "$0")
scriptname="${filename%.*}"
date "+${scriptname} start %Y%m%d_%H%M%S"

set -exo pipefail
export SHELLOPTS

WALLET=$1

gcmd="goal -w ${WALLET}"

ACCOUNT=$(${gcmd} account list|awk '{ print $3 }')

# Easier than prefixing all of the generated files.
cd "$TEMPDIR"

# A program that only approves when its first argument is the passphrase, so
# that the arguments are demonstrably reaching it.
cat > salted.teal <<EOF
#pragma version 6
arg 0
byte "open sesame"
==
EOF

# compile reports both of a program's addresses: the program hash it has always
# had, and the salted one that no Ed25519 key can claim.
COMPILED=$(${gcmd} clerk compile -n salted.teal)
LEGACY=$(echo "$COMPILED" | awk '{ print $2 }')
SALTED=$(echo "$COMPILED" | sed 's/.*(pq: \(.*\))/\1/')

echo "legacy: $LEGACY"
echo "salted: $SALTED"

if [ "$LEGACY" = "$SALTED" ]; then
    date "+${scriptname} FAIL the two addresses should differ %Y%m%d_%H%M%S"
    false
fi

# Fund the salted account below one reward unit to avoid balance drift.
FUNDING=900000
${gcmd} clerk send -a "${FUNDING}" -f "${ACCOUNT}" -t "${SALTED}"

# Spending from the salted account needs no key and no signature: the address
# commits to the program, so running it is the whole authorization.
${gcmd} clerk send --salted -F salted.teal --argb64 "$(printf 'open sesame' | base64)" \
        -a 1000 -f "${SALTED}" -t "${ACCOUNT}"

# The arguments are not signed, so anyone may rewrite them, but only the ones
# the program accepts get it to approve.
set +o pipefail
${gcmd} clerk send --salted -F salted.teal --argb64 "$(printf 'abracadabra' | base64)" \
        -a 1000 -f "${SALTED}" -t "${ACCOUNT}" 2>&1 | grep "rejected by logic" || exit 1
set -o pipefail

# Naming the salted account is enough to pick the salted form, so --salted is
# only needed when nothing else says which of the two addresses is meant.
${gcmd} clerk send -F salted.teal --argb64 "$(printf 'open sesame' | base64)" \
        -a 1000 -f "${SALTED}" -t "${ACCOUNT}"

# The legacy address still works, and is still what a bare -F means.
${gcmd} clerk send -a 500000 -f "${ACCOUNT}" -t "${LEGACY}"
${gcmd} clerk send -F salted.teal --argb64 "$(printf 'open sesame' | base64)" \
        -a 1000 -t "${ACCOUNT}"

BALANCE=$(${gcmd} account balance -a "${SALTED}" | awk '{ print $1 }')
EXPECT=$((FUNDING - 2 * (1000 + 1000)))
if [ "$BALANCE" -ne "$EXPECT" ]; then
    date "+${scriptname} FAIL wanted balance=${EXPECT} but got ${BALANCE} %Y%m%d_%H%M%S"
    false
fi

date "+${scriptname} OK %Y%m%d_%H%M%S"
