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

APPID=$(${gcmd} app create --creator "${ACCOUNT}" --approval-prog=${TEAL}/check_creatable_id.teal --global-byteslices 0 --global-ints 0 --local-byteslices 0 --local-ints 0  --clear-prog=${TEAL}/approve-all.teal --app-arg=str:skipcreation | grep Created | awk '{ print $6 }')

# ==============================
# > Get own creatable ID test
# ==============================

${gcmd} app create --creator "${ACCOUNT}" --approval-prog=${TEAL}/check_creatable_id.teal --global-byteslices 0 --global-ints 0 --local-byteslices 0 --local-ints 0  --clear-prog=${TEAL}/approve-all.teal --app-arg=str:dontskip --app-arg=int:0

# ==============================
# > Asset and application test
# ==============================

# Create asset transaction
${gcmd} asset create --creator "${ACCOUNT}" --total 1000 --unitname "" --asseturl "" --decimals 0 --out "$TEMPDIR/unsigned_asset_create.txn"

# App call transaction to check asset creatable ID
${gcmd} app call --app-id="$APPID" --from="$ACCOUNT" --app-arg=str:skipcreation --app-arg=int:0 --out "$TEMPDIR/unsigned_asset_check_app_call.txn"

# Create app transaction
${gcmd} app create --creator "${ACCOUNT}" --approval-prog=${TEAL}/approve-all.teal --global-byteslices 0 --global-ints 0 --local-byteslices 0 --local-ints 0  --clear-prog=${TEAL}/approve-all.teal --out "$TEMPDIR/unsigned_app_create.txn"

# App call transaction to check app creatable ID
${gcmd} app call --app-id="$APPID" --from="$ACCOUNT" --app-arg=str:skipcreation --app-arg=int:2 --out "$TEMPDIR/unsigned_app_check_app_call.txn"

# Group transactions
cat "$TEMPDIR/unsigned_asset_create.txn" "$TEMPDIR/unsigned_asset_check_app_call.txn" "$TEMPDIR/unsigned_app_create.txn" "$TEMPDIR/unsigned_app_check_app_call.txn" > "$TEMPDIR/combined_transactions.txn"
${gcmd} clerk group -i "$TEMPDIR/combined_transactions.txn" -o "$TEMPDIR/grouped_transactions.txn"

# Sign and send
${gcmd} clerk sign -i "$TEMPDIR/grouped_transactions.txn" -o "$TEMPDIR/signed.txn"
${gcmd} clerk rawsend -f "$TEMPDIR/signed.txn"

date "+${scriptname} OK %Y%m%d_%H%M%S"