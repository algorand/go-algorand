#!/bin/bash

filename=$(basename "$0")
scriptname="${filename%.*}"
date "+${scriptname} start %Y%m%d_%H%M%S"

set -e
set -x
set -o pipefail
export SHELLOPTS

WALLET=$1

gcmd="goal -w ${WALLET}"

ACCOUNT=$(${gcmd} account list|awk '{ print $3 }')
ASSET_NAME='Birlot : décollage vs. ࠶🦪'

set +o pipefail
# longer than 32-byte ASA URLs should fail
${gcmd} asset create \
    --creator "${ACCOUNT}" \
    --name "${ASSET_NAME}" \
    --unitname amisc \
    --total 1000000000000 \
    --asseturl "123456789012345678901234567890123" 2>&1 \
    | grep "is too long (max 32 bytes)"
set -o pipefail

date "+${scriptname} finish %Y%m%d_%H%M%S"
