#!/bin/bash

date '+asset-misc start %Y%m%d_%H%M%S'

set -e
set -x
set -o pipefail
export SHELLOPTS

WALLET=$1

gcmd="goal -w ${WALLET}"

ACCOUNT=$(${gcmd} account list|awk '{ print $3 }')
ACCOUNTB=$(${gcmd} account new|awk '{ print $6 }')
ACCOUNTC=$(${gcmd} account new|awk '{ print $6 }')
ACCOUNTD=$(${gcmd} account new|awk '{ print $6 }')
ACCOUNTE=$(${gcmd} account new|awk '{ print $6 }')

ASSET_NAME='Birlot : décollage vs. ࠶🦪'

# to ensure IPFS URLs longer than 32 characters are supported
ASSET_URL="/ipfs/QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco/wiki/Verifiable_random_function.html"

${gcmd} asset create --creator "${ACCOUNT}" --name "${ASSET_NAME}" --unitname amisc --total 1000000000000 --asseturl "${ASSET_URL}"

ASSET_ID=$(${gcmd} asset info --creator $ACCOUNT --unitname amisc|grep 'Asset ID'|awk '{ print $3 }')

${gcmd} clerk send --from ${ACCOUNT} --to ${ACCOUNTB} --amount 1000000
${gcmd} clerk send --from ${ACCOUNT} --to ${ACCOUNTC} --amount 1000000
${gcmd} clerk send --from ${ACCOUNT} --to ${ACCOUNTD} --amount 1000000

# opt in to asset
${gcmd} asset send --assetid ${ASSET_ID} -f ${ACCOUNTB} -t ${ACCOUNTB} -a 0
${gcmd} asset send --assetid ${ASSET_ID} -f ${ACCOUNTC} -t ${ACCOUNTC} -a 0
${gcmd} asset send --assetid ${ASSET_ID} -f ${ACCOUNTD} -t ${ACCOUNTD} -a 0

# fund asset
${gcmd} asset send --assetid ${ASSET_ID} -f ${ACCOUNT} -t ${ACCOUNTB} -a 1000

# asset send some and close the rest
${gcmd} asset send --assetid ${ASSET_ID} -f ${ACCOUNTB} -t ${ACCOUNTC} -a 100 --close-to ${ACCOUNTD}

if ${gcmd} account info -a ${ACCOUNTC} |grep "${ASSET_NAME}"|grep -c -q 'balance 100 '; then
    echo ok
else
    date '+asset-misc asset balance error %Y%m%d_%H%M%S'
    exit 1
fi

# Test Scenario - check addresses are set correctly
# case 1: asset created without specifying manager, reserve, freezer, or clawback
MANAGER_ADDRESS=$(${gcmd} asset info --assetid ${ASSET_ID} |grep 'Manager address'|awk '{ print $3 }')
RESERVE_ADDRESS=$(${gcmd} asset info --assetid ${ASSET_ID} |grep 'Reserve address'|awk '{ print $3 }')
FREEZE_ADDRESS=$(${gcmd} asset info --assetid ${ASSET_ID} |grep 'Freeze address'|awk '{ print $3 }')
CLAWBACK_ADDRESS=$(${gcmd} asset info --assetid ${ASSET_ID} |grep 'Clawback address'|awk '{ print $3 }')

# check manager, reserve, freeze, and clawback are by default the creator
if [ "$MANAGER_ADDRESS" = "$ACCOUNT" ] \
    && [ "$RESERVE_ADDRESS" = "$ACCOUNT" ] \
    && [ "$FREEZE_ADDRESS" = "$ACCOUNT" ] \
    && [ "$CLAWBACK_ADDRESS" = "$ACCOUNT" ]; then
    echo ok
else
    date '+asset-misc asset manager, reserve, freezer, and clawback should be creator error %Y%m%d_%H%M%S'
    exit 1
fi

# case 2: asset created with no manager, no reserve, no freezer, and no clawback
${gcmd} asset create --creator "${ACCOUNT}" --no-manager --no-reserve --no-freezer --no-clawback --name "${ASSET_NAME}" --unitname iamisc --total 1000000000000 --asseturl "${ASSET_URL}"

IMMUTABLE_ASSET_ID=$(${gcmd} asset info --creator $ACCOUNT --unitname iamisc|grep 'Asset ID'|awk '{ print $3 }')

IMMUTABLE_MANAGER_ADDRESS=$(${gcmd} asset info --assetid ${IMMUTABLE_ASSET_ID} |grep 'Manager address'|awk '{ print $3 }')
IMMUTABLE_RESERVE_ADDRESS=$(${gcmd} asset info --assetid ${IMMUTABLE_ASSET_ID} |grep 'Reserve address'|awk -F "[()]" '{ print $2 }')
IMMUTABLE_FREEZE_ADDRESS=$(${gcmd} asset info --assetid ${IMMUTABLE_ASSET_ID} |grep 'Freeze address'|awk '{ print $3 }')
IMMUTABLE_CLAWBACK_ADDRESS=$(${gcmd} asset info --assetid ${IMMUTABLE_ASSET_ID} |grep 'Clawback address'|awk '{ print $3 }')

# goal asset info returns the creator's address as the reserve address when reserve address is empty
# check goal/asset.go
if [ "$IMMUTABLE_MANAGER_ADDRESS" = "" ] \
    && [ "$IMMUTABLE_RESERVE_ADDRESS" = "Empty. Defaulting to creator" ] \
    && [ "$IMMUTABLE_FREEZE_ADDRESS" = "" ] \
    && [ "$IMMUTABLE_CLAWBACK_ADDRESS" = "" ]; then
    echo ok
else
    date '+asset-misc immutable asset manager/reserve/freezer/clawback addresses error %Y%m%d_%H%M%S'
    exit 1
fi

# case 3: asset created with manager, reserve, freezer, and clawback different from the creator
${gcmd} asset create --creator "${ACCOUNT}" --manager "${ACCOUNTB}" --reserve "${ACCOUNTC}" --freezer "${ACCOUNTD}" --clawback "${ACCOUNTE}" --name "${ASSET_NAME}" --unitname dma --total 1000000000000 --asseturl "${ASSET_URL}"

DIFF_MANAGER_ASSET_ID=$(${gcmd} asset info --creator $ACCOUNT --unitname dma|grep 'Asset ID'|awk '{ print $3 }')

DMA_MANAGER_ADDRESS=$(${gcmd} asset info --assetid ${DIFF_MANAGER_ASSET_ID} |grep 'Manager address'|awk '{ print $3 }')
DMA_RESERVE_ADDRESS=$(${gcmd} asset info --assetid ${DIFF_MANAGER_ASSET_ID} |grep 'Reserve address'|awk '{ print $3 }')
DMA_FREEZE_ADDRESS=$(${gcmd} asset info --assetid ${DIFF_MANAGER_ASSET_ID} |grep 'Freeze address'|awk '{ print $3 }')
DMA_CLAWBACK_ADDRESS=$(${gcmd} asset info --assetid ${DIFF_MANAGER_ASSET_ID} |grep 'Clawback address'|awk '{ print $3 }')

if [ "$DMA_MANAGER_ADDRESS" = "$ACCOUNTB" ] \
    && [ "$DMA_RESERVE_ADDRESS" = "$ACCOUNTC" ] \
    && [ "$DMA_FREEZE_ADDRESS" = "$ACCOUNTD" ] \
    && [ "$DMA_CLAWBACK_ADDRESS" = "$ACCOUNTE" ]; then
    echo ok
else
    date '+asset-misc asset addresses with diff manager/reserve/freeze/clawback error %Y%m%d_%H%M%S'
    exit 1
fi

# Test Scenario - check if asset is created successfully when passed in different combination of flags for addresses
# case 1: create asset with both manager flag and no-manager flag
if ${gcmd} asset create --creator "${ACCOUNT}" --no-manager --manager "${ACCOUNTB}" --name "${ASSET_NAME}" --unitname errmisc --total 1000000000000 --asseturl "${ASSET_URL}"; then
    date '+asset-misc asset with --manager and --no-manager flags created successfully error %Y%m%d_%H%M%S'
    exit 1
else
    echo "Expected. Cannot create asset with both manager flag and no-manager flag"
fi

# case 2: create asset with both reserve flag and no-reserve flag
if ${gcmd} asset create --creator "${ACCOUNT}" --no-reserve --reserve "${ACCOUNTC}" --name "${ASSET_NAME}" --unitname errmisc --total 1000000000000 --asseturl "${ASSET_URL}"; then
    date '+asset-misc asset with --reserve and --no-reserve flags created successfully error %Y%m%d_%H%M%S'
    exit 1
else
    echo "Expected. Cannot create asset with both reserve flag and no-reserve flag"
fi

# case 3: create asset with both freezer flag and no-freezer flag
if ${gcmd} asset create --creator "${ACCOUNT}" --no-freezer --freezer "${ACCOUNTD}" --name "${ASSET_NAME}" --unitname errmisc --total 1000000000000 --asseturl "${ASSET_URL}"; then
    date '+asset-misc asset with --freezer and --no-freezer flags created successfully error %Y%m%d_%H%M%S'
    exit 1
else
    echo "Expected. Cannot create asset with both freezer flag and no-freezer flag"
fi

# case 4: create asset with both clawback flag and no-clawback flag
if ${gcmd} asset create --creator "${ACCOUNT}" --no-clawback --clawback "${ACCOUNTE}" --name "${ASSET_NAME}" --unitname errmisc --total 1000000000000 --asseturl "${ASSET_URL}"; then
    date '+asset-misc asset with --clawback and --no-clawback flags created successfully error %Y%m%d_%H%M%S'
    exit 1
else
    echo "Expected. Cannot create asset with both clawback flag and no-clawback flag"
fi

# case 5: create asset with reserve flag, no-freezer flag and no-clawback flag
if ${gcmd} asset create --creator "${ACCOUNT}" --no-freezer --no-clawback --reserve "${ACCOUNTE}" --name "${ASSET_NAME}" --unitname errmisc --total 1000000000000 --asseturl "${ASSET_URL}"; then
    echo "ok"
else
    date '+asset-misc asset with independent flags created unsuccessfully error %Y%m%d_%H%M%S'
    exit 1
fi

date '+asset-misc finish %Y%m%d_%H%M%S'
