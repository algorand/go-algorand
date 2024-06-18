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

# wait a few rounds for the asset optins to get into the db, since the account asset info endpoint
# does not look at in memory deltas
${gcmd} clerk send -a 0 -f ${ACCOUNTA} -t ${ACCOUNTB}
${gcmd} clerk send -a 0 -f ${ACCOUNTA} -t ${ACCOUNTB}
${gcmd} clerk send -a 0 -f ${ACCOUNTA} -t ${ACCOUNTB}

# query account assets w/ details, (1)
RES=$(${gcmd} account assetdetails -a ${ACCOUNTB})
if [[ ${RES} != *"Account: ${ACCOUNTB}"* ]]; then
    date '+goal-account-asset-test assetdetails (1) should be for correct account %Y%m%d_%H%M%S'
    false
fi
if [[ ${RES} != *"Asset ID: ${ASSET_A_ID}"$'\n'"    Amount: 0"* ]]; then
    date '+goal-account-asset-test assetdetails (1) should contain asset A %Y%m%d_%H%M%S'
    false
fi
if [[ ${RES} != *"Asset ID: ${ASSET_B_ID}"$'\n'"    Amount: 0"* ]]; then
    date '+goal-account-asset-test assetdetails (1) should contain asset B %Y%m%d_%H%M%S'
    false
fi
if [[ ${RES} != *"Asset ID: ${ASSET_C_ID}"$'\n'"    Amount: 0"* ]]; then
    date '+goal-account-asset-test assetdetails (1) should contain asset C %Y%m%d_%H%M%S'
    false
fi
if [[ ${RES} != *"Asset ID: ${ASSET_D_ID}"$'\n'"    Amount: 0"* ]]; then
    date '+goal-account-asset-test assetdetails (1) should contain asset D %Y%m%d_%H%M%S'
    false
fi

# query account assets w/ details, limit 2, next set to asset B, (2)
RES=$(${gcmd} account assetdetails -a ${ACCOUNTB} -l 2 -n ${ASSET_B_ID})
if [[ ${RES} != *"Account: ${ACCOUNTB}"* ]]; then
    date '+goal-account-asset-test assetdetails (2) should be for correct account %Y%m%d_%H%M%S'
    false
fi
if [[ ${RES} == *"Asset ID: ${ASSET_A_ID}"* ]]; then
    date '+goal-account-asset-test assetdetails (2) should not contain asset A %Y%m%d_%H%M%S'
    false
fi
if [[ ${RES} == *"Asset ID: ${ASSET_B_ID}"* ]]; then
    date '+goal-account-asset-test assetdetails (2) should not contain asset B %Y%m%d_%H%M%S'
    false
fi
if [[ ${RES} != *"Asset ID: ${ASSET_C_ID}"$'\n'"    Amount: 0"* ]]; then
    date '+goal-account-asset-test assetdetails (2) should contain asset C %Y%m%d_%H%M%S'
    false
fi
if [[ ${RES} != *"Asset ID: ${ASSET_D_ID}"$'\n'"    Amount: 0"* ]]; then
    date '+goal-account-asset-test assetdetails (2) should contain asset D %Y%m%d_%H%M%S'
    false
fi

# delete one of the asset
${gcmd} asset destroy --assetid ${ASSET_B_ID} --creator ${ACCOUNTA} --signer ${ACCOUNTA}

# wait a few rounds for the deletion to get into the db
${gcmd} clerk send -a 0 -f ${ACCOUNTA} -t ${ACCOUNTB}
${gcmd} clerk send -a 0 -f ${ACCOUNTA} -t ${ACCOUNTB}
${gcmd} clerk send -a 0 -f ${ACCOUNTA} -t ${ACCOUNTB}

# query account assets w/ details after deletion, (3)
RES=$(${gcmd} account assetdetails -a ${ACCOUNTB})
if [[ ${RES} != *"Account: ${ACCOUNTB}"* ]]; then
    date '+goal-account-asset-test assetdetails (3) should be for correct account %Y%m%d_%H%M%S'
    false
fi
if [[ ${RES} != *"Asset ID: ${ASSET_A_ID}"$'\n'"    Amount: 0"* ]]; then
    date '+goal-account-asset-test assetdetails (3) should contain asset A %Y%m%d_%H%M%S'
    false
fi
# ensure asset B is still present, but its params are unavailable
if [[ ${RES} != *"Asset ID: ${ASSET_B_ID}"$'\n'"    Amount (without formatting): 0"* ]]; then
    date '+goal-account-asset-test assetdetails (3) should contain asset B without asset params %Y%m%d_%H%M%S'
    false
fi
if [[ ${RES} != *"Asset ID: ${ASSET_C_ID}"$'\n'"    Amount: 0"* ]]; then
    date '+goal-account-asset-test assetdetails (3) should contain asset C %Y%m%d_%H%M%S'
    false
fi
if [[ ${RES} != *"Asset ID: ${ASSET_D_ID}"$'\n'"    Amount: 0"* ]]; then
    date '+goal-account-asset-test assetdetails (3) should contain asset D %Y%m%d_%H%M%S'
    false
fi

# check account info display
RES=$(${gcmd} account info -a ${ACCOUNTB})

# check result
EXPECTED="ID ${ASSET_B_ID}, <deleted/unknown asset>"

if [[ ${RES} != *"${EXPECTED}"* ]]; then
    date '+goal-account-asset-test should list account info with deleted asset expected line %Y%m%d_%H%M%S'
    false
fi
