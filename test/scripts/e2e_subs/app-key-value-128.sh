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

APPID=$(${gcmd} app create --creator "${ACCOUNT}" --approval-prog=${TEAL}/state-rw.teal --global-byteslices 2 --global-ints 0 --local-byteslices 2 --local-ints 0  --clear-prog=${TEAL}/approve-all.teal | grep Created | awk '{ print $6 }')

function call {
    ${gcmd} app call --app-id=$APPID --from=$ACCOUNT --app-arg=str:$1  --app-arg=str:$2  --app-arg=str:$3  --app-arg=str:$4
}

BIG64="1234567890123456789012345678901234567890123456789012345678901234"

# This should work because the value is longer than 64, but the sum is still under 128
call write global hello ${BIG64}EVENLONGEREVENLONGEREVENLONGEREVENLONGER
call check global hello ${BIG64}EVENLONGEREVENLONGEREVENLONGEREVENLONGER

# And this is on the edge of ok - both are 64
call write global $BIG64 $BIG64
call check global $BIG64 $BIG64

# This should not work because the key 64 and the value is 65
set +o pipefail
# This value so big that it fails before the sum is considered
call write global $BIG64 ${BIG64}${BIG64}X 2>&1 | grep "value too long" | grep length
# This causes problems because the sum is too big
call write global $BIG64 ${BIG64}X 2>&1 | grep "value too long" | grep sum
set -o pipefail


# Same tests below, but on LOCAL state (so first have to deal with opt-in)

set +o pipefail
call check local hello xyz 2>&1 | grep "has not opted in"
set -o pipefail

${gcmd} app optin --app-id "$APPID" --from "${ACCOUNT}"

# This should work because the value is longer than 64, but the sum is still under 128
call write local hello ${BIG64}EVENLONGEREVENLONGEREVENLONGEREVENLONGER
call check local hello ${BIG64}EVENLONGEREVENLONGEREVENLONGEREVENLONGER

# And this is on the edge of ok - both are 64
call write local $BIG64 $BIG64
call check local $BIG64 $BIG64

# This should not work because the key 64 and the value is 65
set +o pipefail
call write local $BIG64 ${BIG64}X 2>&1 | grep "value too long"
set -o pipefail


date "+${scriptname} OK %Y%m%d_%H%M%S"
