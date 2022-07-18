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

# Version 7 clear program
printf '#pragma version 7\nint 1' > "${TEMPDIR}/clear.teal"

APPID=$(${gcmd} app create --creator "$ACCOUNT" --approval-prog=${TEAL}/boxes.teal --clear-prog "$TEMPDIR/clear.teal" --global-byteslices 0 --global-ints 0 --local-byteslices 0 --local-ints 0 | grep Created | awk '{ print $6 }')

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

# Confirm that we can get a list of boxes belonging to a particular application
BOX_LIST=$(${gcmd} app box list --app-id "$APPID")
EXPECTED="str:box1
str:with spaces
str:base64
b64:AQIDBA=="

# shellcheck disable=SC2059
[ "$(printf "$BOX_LIST" | sort)" = "$(printf "$EXPECTED" | sort)" ]

# Confirm that we can limit the number of boxes returned
BOX_LIST=$(${gcmd} app box list --app-id "$APPID" --max 1)
[ "$(wc -l <<< "$BOX_LIST")" = "1" ] # only one line
# shellcheck disable=SC2143
[ "$(grep -w "$BOX_LIST" <<< "$EXPECTED")" ]

date "+${scriptname} OK %Y%m%d_%H%M%S"
