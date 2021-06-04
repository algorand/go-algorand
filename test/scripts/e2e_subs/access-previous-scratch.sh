#!/bin/bash

filename=$(basename "$0")
scriptname="${filename%.*}"
date "+${scriptname} start %Y%m%d_%H%M%S"

set -e
set -x
set -o pipefail
export SHELLOPTS

WALLET=$1

TEAL=test/scripts/e2e_subs/tealprogs

gcmd="goal -w ${WALLET}"

ACCOUNT=$(${gcmd} account list|awk '{ print $3 }')

APPID=$(${gcmd} app create --creator "${ACCOUNT}" --approval-prog=${TEAL}/scratch-rw.teal --global-byteslices 0 --global-ints 0 --local-byteslices 0 --local-ints 0  --clear-prog=${TEAL}/approve-all.teal | grep Created | awk '{ print $6 }')

# Create app calls
function create_app_call {
    ${gcmd} app call --app-id="$APPID" --from="$ACCOUNT" --app-arg=str:"$1" --app-arg=int:"$2" --app-arg=int:"$3" --out "$TEMPDIR/$4"
}

create_app_call write 0 1 unsigned_scratch_write.txn
create_app_call check 0 1 unsigned_scratch_check.txn

# Group transactions
cat "$TEMPDIR/unsigned_scratch_write.txn" "$TEMPDIR/unsigned_scratch_check.txn" > "$TEMPDIR/combined_transactions.txn"
${gcmd} clerk group -i "$TEMPDIR/combined_transactions.txn" -o "$TEMPDIR/grouped_transactions.txn"

# Sign and send
${gcmd} clerk sign -i "$TEMPDIR/grouped_transactions.txn" -o "$TEMPDIR/signed.txn"
${gcmd} clerk rawsend -f "$TEMPDIR/signed.txn"

date "+${scriptname} OK %Y%m%d_%H%M%S"