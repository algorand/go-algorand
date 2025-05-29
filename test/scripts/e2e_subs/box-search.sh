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

# Version 8 clear program
printf '#pragma version 8\nint 1' > "${TEMPDIR}/clear.teal"

APPID=$(${gcmd} app create --creator "$ACCOUNT" --approval-prog=${TEAL}/boxes.teal --clear-prog "$TEMPDIR/clear.teal" | grep Created | awk '{ print $6 }')

# Fund the app account 10 algos
APP_ACCOUNT=$(${gcmd} app info --app-id "$APPID" | grep "Application account" | awk '{print $3}')
${gcmd} clerk send --to "$APP_ACCOUNT" --from "$ACCOUNT" --amount 10000000

# Confirm that we are informed if no application boxes exist
BOX_LIST=$(${gcmd} app box list --app-id "$APPID" 2>&1 || true)
EXPECTED="No boxes found for appid $APPID"

[ "$BOX_LIST" = "$EXPECTED" ]

# Confirm that we are informed if a specific application box does not exist
BOX_INFO=$(${gcmd} app box info --app-id "$APPID" --name "str:not_found" 2>&1 || true)
EXPECTED="No box found for appid $APPID with name str:not_found"

[ "$BOX_INFO" = "$EXPECTED" ]

# Confirm that we error for an invalid box name
BOX_NAME="str:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
RES=$(${gcmd} app call --from "$ACCOUNT" --app-id "$APPID" --box "$BOX_NAME" --app-arg "str:create" --app-arg "$BOX_NAME" 2>&1 || true)
EXPECTED="invalid : tx.Boxes[0].Name too long, max len 64 bytes"

if [[ "$RES" != *"$EXPECTED" ]]; then
  date "+${scriptname} unexpected response from goal app call with invalid box name %Y%m%d_%H%M%S"
  false
fi

# Create several boxes
BOX_NAMES=("str:box1" "str:with spaces" "b64:YmFzZTY0" "b64:AQIDBA==") # b64:YmFzZTY0 == str:base64, b64:AQIDBA== is not unicode
BOX_VALUE="box value"
B64_BOX_VALUE="b64:Ym94IHZhbHVlAAAAAAAAAAAAAAAAAAAA"

for BOX_NAME in "${BOX_NAMES[@]}"
do
  # Create the box
  ${gcmd} app call --from "$ACCOUNT" --app-id "$APPID" --box "$BOX_NAME" --app-arg "str:create" --app-arg "$BOX_NAME"

  # Set box value
  ${gcmd} app call --from "$ACCOUNT" --app-id "$APPID" --box "$BOX_NAME" --app-arg "str:set" --app-arg "$BOX_NAME" --app-arg "str:$BOX_VALUE"
done

# Confirm that we can get the values of each individual box
for BOX_NAME in "${BOX_NAMES[@]}"
do
  ${gcmd} app box info --app-id "$APPID" --name "$BOX_NAME"
  NAME=$(${gcmd} app box info --app-id "$APPID" --name "$BOX_NAME" | grep Name | tr -s ' ' | cut -d" " -f2-)
  [ "$NAME" = "$BOX_NAME" ]

  VALUE=$(${gcmd} app box info --app-id "$APPID" --name "$BOX_NAME" | grep Value | tr -s ' ' | cut -d" " -f2-)
  [ "$VALUE" = "$B64_BOX_VALUE" ]
done

# Confirm that the account data representation knows about all the boxes
APP_ACCOUNT_JSON_DUMP=$(${gcmd} account dump --address "$APP_ACCOUNT")
ACTUAL_APP_ACCOUNT_NUM_BOXES=$(printf "$APP_ACCOUNT_JSON_DUMP" | jq '.tbx')
EXPECTED_APP_ACCOUNT_NUM_BOXES=4
ACTUAL_APP_ACCOUNT_BOX_BYTES=$(printf "$APP_ACCOUNT_JSON_DUMP" | jq '.tbxb')
EXPECTED_APP_ACCOUNT_BOX_BYTES=121
[ "$ACTUAL_APP_ACCOUNT_NUM_BOXES" -eq "$EXPECTED_APP_ACCOUNT_NUM_BOXES" ]
[ "$ACTUAL_APP_ACCOUNT_BOX_BYTES" -eq "$EXPECTED_APP_ACCOUNT_BOX_BYTES" ]

# Confirm that we can get a list of boxes belonging to a particular application
BOX_LIST=$(${gcmd} app box list --app-id "$APPID")
EXPECTED="str:box1
str:with spaces
str:base64
b64:AQIDBA=="

# shellcheck disable=SC2059
[ "$(printf "$BOX_LIST" | sort)" = "$(printf "$EXPECTED" | sort)" ]

# Confirm that we can limit the number of boxes returned
BOX_LIST=$(${gcmd} app box list --app-id "$APPID" --max 4)
[ "$(echo "$BOX_LIST" | wc -l)" -eq 4 ] # only one line
# shellcheck disable=SC2143
[ "$(grep -w "$BOX_LIST" <<< "$EXPECTED")" ] # actual box is in the expected list

# Create and set a box in an atomic txn group:

BOX_NAME="str:great box"
echo "Create $BOX_NAME"
${gcmd} app call --from "$ACCOUNT" --app-id "$APPID" --box "$BOX_NAME" --app-arg "str:create" --app-arg "$BOX_NAME" -o "$TEMPDIR/box_create.txn"

echo "Set $BOX_NAME using $BOX_VALUE"
${gcmd} app call --from "$ACCOUNT" --app-id "$APPID" --app-arg "str:set" --app-arg "$BOX_NAME" --app-arg "str:$BOX_VALUE" -o "$TEMPDIR/box_set.txn"

# Group them, sign and broadcast:
cat "$TEMPDIR/box_create.txn" "$TEMPDIR/box_set.txn" > "$TEMPDIR/box_create_n_set.txn"
${gcmd} clerk group -i "$TEMPDIR/box_create_n_set.txn" -o "$TEMPDIR/box_group.txn"
${gcmd} clerk sign -i "$TEMPDIR/box_group.txn" -o "$TEMPDIR/box_group.stx"
${gcmd} clerk rawsend -f "$TEMPDIR/box_group.stx"

echo "Confirm that NAME $BOX_NAME as expected"
${gcmd} app box info --app-id "$APPID" --name "$BOX_NAME"
NAME=$(${gcmd} app box info --app-id "$APPID" --name "$BOX_NAME" | grep Name | tr -s ' ' | cut -d" " -f2-)
[ "$NAME" = "$BOX_NAME" ]

echo "Confirm that VALUE $BOX_VALUE i.e. ($B64_BOX_VALUE) as expected"
VALUE=$(${gcmd} app box info --app-id "$APPID" --name "$BOX_NAME" | grep Value | tr -s ' ' | cut -d" " -f2-)
[ "$VALUE" = "$B64_BOX_VALUE" ]

# Confirm that we can still get the list of boxes
BOX_LIST=$(${gcmd} app box list --app-id "$APPID")
EXPECTED="str:box1
str:with spaces
str:base64
b64:AQIDBA==
str:great box"

# shellcheck disable=SC2059
[ "$(printf "$BOX_LIST" | sort)" = "$(printf "$EXPECTED" | sort)" ]

# Confirm that the account data representation still knows about all the boxes
APP_ACCOUNT_JSON_DUMP=$(${gcmd} account dump --address "$APP_ACCOUNT")
ACTUAL_APP_ACCOUNT_NUM_BOXES=$(printf "$APP_ACCOUNT_JSON_DUMP" | jq '.tbx')
EXPECTED_APP_ACCOUNT_NUM_BOXES=5
ACTUAL_APP_ACCOUNT_BOX_BYTES=$(printf "$APP_ACCOUNT_JSON_DUMP" | jq '.tbxb')
EXPECTED_APP_ACCOUNT_BOX_BYTES=154
[ "$ACTUAL_APP_ACCOUNT_NUM_BOXES" -eq "$EXPECTED_APP_ACCOUNT_NUM_BOXES" ]
[ "$ACTUAL_APP_ACCOUNT_BOX_BYTES" -eq "$EXPECTED_APP_ACCOUNT_BOX_BYTES" ]

date "+${scriptname} OK %Y%m%d_%H%M%S"
