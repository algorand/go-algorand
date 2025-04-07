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

# Confirm that "Boxes:" is the last line when there are no Boxes
BOX_LIST=$(${gcmd} app box list --app-id "$APPID" || true)
[[ "$BOX_LIST" = *"Boxes:" ]] || false

# Confirm that we are informed if a specific application box does not exist
BOX_INFO=$(${gcmd} app box info --app-id "$APPID" --name "str:not_found" 2>&1 || true)
[[ "$BOX_INFO" = *"No box found for appid $APPID with name str:not_found" ]] || false

# Confirm that we error for an invalid box name
BOX_NAME="str:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
RES=$(${gcmd} app call --from "$ACCOUNT" --app-id "$APPID" --box "$BOX_NAME" --app-arg "str:create" --app-arg "$BOX_NAME" 2>&1 || true)
[[ "$RES" = *"invalid : tx.Boxes[0].Name too long, max len 64 bytes" ]] || false

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

# goal app box list only looks at the DB, so wait a few rounds
sleep 10

# Confirm that we can get a list of boxes belonging to a particular application
BOX_LIST=$(${gcmd} app box list --app-id "$APPID")
[[ "$BOX_LIST" = "Round: "* ]] || false
EXPECTED="Boxes:
b64:AQIDBA==
str:base64
str:box1
str:with spaces"
[[ "$BOX_LIST" = *"$EXPECTED" ]] || false

# Confirm that we can limit the number of boxes returned
BOX_LIST=$(${gcmd} app box list --app-id "$APPID" --limit 2)
[ "$(echo "$BOX_LIST" | wc -l)" -eq 5 ] # Round:, NextToken:, Boxes:, 2 actual responses
[[ "$BOX_LIST" != *str:with\ spaces* ]] || false # 4th box doesn't appear
[[ "$BOX_LIST" = *str:box1*Boxes:* ]] || false # 3rd box is this the NextToken (comes before "Boxes:")

# Fetch the final two boxes
BOX_LIST=$(${gcmd} app box list --app-id "$APPID" --limit 2 --next str:box1)
[ "$(echo "$BOX_LIST" | wc -l)" -eq 4 ] # Round:, Boxes:, 2 actual responses
[[ "$BOX_LIST" != *NextToken* ]] || false # No NextToken
[[ "$BOX_LIST" = *Boxes:*str:box1* ]] || false
[[ "$BOX_LIST" = *Boxes:*str:with\ spaces* ]] || false

# Confirm that we can use prefix to get only boxes that start with "bo"
BOX_LIST=$(${gcmd} app box list --app-id "$APPID" --prefix str:bo)
[ "$(echo "$BOX_LIST" | wc -l)" -eq 3 ] # Round:, Boxes:, 1 actual response
[[ "$BOX_LIST" != *Boxes:*str:base64* ]] || false
[[ "$BOX_LIST" = *Boxes:*str:box1* ]] || false

# Confirm that we can use prefix to get only boxes that start with "b"
BOX_LIST=$(${gcmd} app box list --app-id "$APPID" --prefix str:b)
[ "$(echo "$BOX_LIST" | wc -l)" -eq 4 ] # Round:, Boxes:, 2 actual responses
[[ "$BOX_LIST" = *Boxes:*str:base64* ]] || false
[[ "$BOX_LIST" = *Boxes:*str:box1* ]] || false


# Create and set a box in an atomic txn group:

BOX_NAME="str:great box"
echo "Create $BOX_NAME"
${gcmd} app call --from "$ACCOUNT" --app-id "$APPID" --box "$BOX_NAME" --app-arg "str:create" --app-arg "$BOX_NAME" -o "$TEMPDIR/box_create.txn"

echo "Set $BOX_NAME using str:GREAT"
GREAT_VALUE=123456789012345678901234
${gcmd} app call --from "$ACCOUNT" --app-id "$APPID" --app-arg "str:set" --app-arg "$BOX_NAME" --app-arg "str:$GREAT_VALUE" -o "$TEMPDIR/box_set.txn"

# Group them, sign and broadcast:
cat "$TEMPDIR/box_create.txn" "$TEMPDIR/box_set.txn" > "$TEMPDIR/box_create_n_set.txn"
${gcmd} clerk group -i "$TEMPDIR/box_create_n_set.txn" -o "$TEMPDIR/box_group.txn"
${gcmd} clerk sign -i "$TEMPDIR/box_group.txn" -o "$TEMPDIR/box_group.stx"
COMMIT=$(${gcmd} clerk rawsend -f "$TEMPDIR/box_group.stx" | grep "committed in round" | head -1 | awk '{print $6}')
echo "Last box made in $COMMIT"

echo "Confirm the NAME is $BOX_NAME"
${gcmd} app box info --app-id "$APPID" --name "$BOX_NAME"
NAME=$(${gcmd} app box info --app-id "$APPID" --name "$BOX_NAME" | grep Name | tr -s ' ' | cut -d" " -f2-)
[ "$NAME" = "$BOX_NAME" ]

VALUE=$(${gcmd} app box info --app-id "$APPID" --name "$BOX_NAME" | grep Value | tr -s ' ' | cut -d" " -f2-)
[ "$VALUE" = str:$GREAT_VALUE ]


# Confirm that we can still get the list of boxes (need to keep asking
# until the returned results are for $ROUND)
retry=0
while [ $retry -lt 10 ]; do
    BOX_LIST=$(${gcmd} app box list --app-id "$APPID")
    ROUND=$(echo "$BOX_LIST" | awk '/Round: / {print $2}')
    if [[ "$COMMIT" == "$ROUND" ]]; then
        break
    fi
    retry=$((retry + 1))
    sleep 2
done

EXPECTED="Boxes:
b64:AQIDBA==
str:base64
str:box1
str:great box
str:with spaces"
[[ "$BOX_LIST" = *"$EXPECTED" ]] || false

# Confirm that values are available
BOX_LIST=$(${gcmd} app box list --app-id "$APPID" --values)
EXPECTED="Boxes:
b64:AQIDBA== : $B64_BOX_VALUE
str:base64 : $B64_BOX_VALUE
str:box1 : $B64_BOX_VALUE
str:great box : str:$GREAT_VALUE
str:with spaces : $B64_BOX_VALUE"
[[ "$BOX_LIST" = *"$EXPECTED" ]] || false

# Confirm that the account data representation still knows about all the boxes
APP_ACCOUNT_JSON_DUMP=$(${gcmd} account dump --address "$APP_ACCOUNT")
ACTUAL_APP_ACCOUNT_NUM_BOXES=$(printf "$APP_ACCOUNT_JSON_DUMP" | jq '.tbx')
EXPECTED_APP_ACCOUNT_NUM_BOXES=5
ACTUAL_APP_ACCOUNT_BOX_BYTES=$(printf "$APP_ACCOUNT_JSON_DUMP" | jq '.tbxb')
EXPECTED_APP_ACCOUNT_BOX_BYTES=154
[ "$ACTUAL_APP_ACCOUNT_NUM_BOXES" -eq "$EXPECTED_APP_ACCOUNT_NUM_BOXES" ]
[ "$ACTUAL_APP_ACCOUNT_BOX_BYTES" -eq "$EXPECTED_APP_ACCOUNT_BOX_BYTES" ]

date "+${scriptname} OK %Y%m%d_%H%M%S"
