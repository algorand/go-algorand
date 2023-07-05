#!/bin/bash

date '+goal-account-asset-test start %Y%m%d_%H%M%S'

set -e
set -x
set -o pipefail
export SHELLOPTS

WALLET=$1

gcmd="goal -w ${WALLET}"

ACCOUNTA=$(${gcmd} account list|awk '{ print $3 }')
ACCOUNTB=$(${gcmd} account new|awk '{ print $6 }')

ASSET_INDEX_PATTERN='Created asset with asset index [[:digit:]]+'

# fund account B a bit
${gcmd} clerk send -a 100000000 -f ${ACCOUNTA} -t ${ACCOUNTB}

# create all assets
RES=$(${gcmd} asset create --name "asset-a" --creator ${ACCOUNTA} --total 100 --no-clawback --no-freezer --manager ${ACCOUNTA} --no-reserve --signer ${ACCOUNTA})
ASSET_A_ID=$(echo ${RES} | grep -Eo "${ASSET_INDEX_PATTERN}" | grep -Eo '[[:digit:]]+')

RES=$(${gcmd} asset create --name "asset-b" --creator ${ACCOUNTA} --total 200 --no-clawback --no-freezer --manager ${ACCOUNTA} --no-reserve --signer ${ACCOUNTA})
ASSET_B_ID=$(echo ${RES} | grep -Eo "${ASSET_INDEX_PATTERN}" | grep -Eo '[[:digit:]]+')

RES=$(${gcmd} asset create --name "asset-c" --creator ${ACCOUNTA} --total 300 --no-clawback --no-freezer --manager ${ACCOUNTA} --no-reserve --signer ${ACCOUNTA})
ASSET_C_ID=$(echo ${RES} | grep -Eo "${ASSET_INDEX_PATTERN}" | grep -Eo '[[:digit:]]+')

RES=$(${gcmd} asset create --name "asset-d" --creator ${ACCOUNTA} --total 400 --no-clawback --no-freezer --manager ${ACCOUNTA} --no-reserve --signer ${ACCOUNTA})
ASSET_D_ID=$(echo ${RES} | grep -Eo "${ASSET_INDEX_PATTERN}" | grep -Eo '[[:digit:]]+')

# opt in all assets
${gcmd} asset optin --account ${ACCOUNTB} --assetid ${ASSET_A_ID} --signer ${ACCOUNTB}
${gcmd} asset optin --account ${ACCOUNTB} --assetid ${ASSET_B_ID} --signer ${ACCOUNTB}
${gcmd} asset optin --account ${ACCOUNTB} --assetid ${ASSET_C_ID} --signer ${ACCOUNTB}
${gcmd} asset optin --account ${ACCOUNTB} --assetid ${ASSET_D_ID} --signer ${ACCOUNTB}

# displays held assets
${gcmd} account info -a ${ACCOUNTB}

# delete one of the asset
${gcmd} asset destroy --assetid ${ASSET_B_ID} --creator ${ACCOUNTA} --signer ${ACCOUNTA}

# check account info display
RES=$(${gcmd} account info -a ${ACCOUNTB})

# check result
EXPECTED="ID ${ASSET_B_ID}, <deleted/unknown asset>"

if [[ ${RES} != *"${EXPECTED}"* ]]; then
    date '+goal-account-asset-test should list account info with deleted asset expected line %Y%m%d_%H%M%S'
    false
fi
