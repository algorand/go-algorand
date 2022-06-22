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
APP_ACCOUNT=$(goal app info --app-id "$APPID" | grep "Application account" | awk '{print $3}')
${gcmd} clerk send --to "$APP_ACCOUNT" --from "$ACCOUNT" --amount 10000000

# Create several boxes
BOX_NAMES=("str:box1" "str:with spaces" "b64:YmFzZTY0")
BOX_VALUE="box value"

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
  VALUE=$(${gcmd} app box info --app-id "$APPID" --name "$BOX_NAME" | grep Value | cut -d" " -f2-)
  [ "$VALUE" = "$BOX_VALUE" ]
done

# TODO: Confirm that we can get a list of boxes belonging to a particular application

date "+${scriptname} OK %Y%m%d_%H%M%S"
