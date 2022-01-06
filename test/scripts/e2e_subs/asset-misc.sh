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

# create asset with no manager, no freezer, and no clawback
${gcmd} asset create --creator "${ACCOUNT}" --no-manager --no-freezer --no-clawback --name "${ASSET_NAME}" --unitname iamisc --total 1000000000000 --asseturl "${ASSET_URL}"

IMMUTABLE_ASSET_ID=$(${gcmd} asset info --creator $ACCOUNT --unitname iamisc|grep 'Asset ID'|awk '{ print $3 }')

MANAGER_ADDRESS=$(${gcmd} asset info --assetid ${IMMUTABLE_ASSET_ID} |grep 'Manager address'|awk '{ print $3 }')
RESERVE_ADDRESS=$(${gcmd} asset info --assetid ${IMMUTABLE_ASSET_ID} |grep 'Reserve address'|awk '{ print $3 }')
FREEZE_ADDRESS=$(${gcmd} asset info --assetid ${IMMUTABLE_ASSET_ID} |grep 'Freeze address'|awk '{ print $3 }')
CLAWBACK_ADDRESS=$(${gcmd} asset info --assetid ${IMMUTABLE_ASSET_ID} |grep 'Clawback address'|awk '{ print $3 }')

if [ "$MANAGER_ADDRESS" = "" ] \
    && [ "$RESERVE_ADDRESS" = "$ACCOUNT" ] \
    && [ "$FREEZE_ADDRESS" = "" ] \
    && [ "$CLAWBACK_ADDRESS" = "" ]; then
    echo ok
else
    date '+asset-misc immutable asset info error %Y%m%d_%H%M%S'
    exit 1
fi

# create asset with a manager that is different from the creator
${gcmd} asset create --creator "${ACCOUNT}" --manager "${ACCOUNTB}" --name "${ASSET_NAME}" --unitname dma --total 1000000000000 --asseturl "${ASSET_URL}"

DIFF_MANAGER_ASSET_ID=$(${gcmd} asset info --creator $ACCOUNT --unitname dma|grep 'Asset ID'|awk '{ print $3 }')

DMA_MANAGER_ADDRESS=$(${gcmd} asset info --assetid ${DIFF_MANAGER_ASSET_ID} |grep 'Manager address'|awk '{ print $3 }')
DMA_RESERVE_ADDRESS=$(${gcmd} asset info --assetid ${DIFF_MANAGER_ASSET_ID} |grep 'Reserve address'|awk '{ print $3 }')
DMA_FREEZE_ADDRESS=$(${gcmd} asset info --assetid ${DIFF_MANAGER_ASSET_ID} |grep 'Freeze address'|awk '{ print $3 }')
DMA_CLAWBACK_ADDRESS=$(${gcmd} asset info --assetid ${DIFF_MANAGER_ASSET_ID} |grep 'Clawback address'|awk '{ print $3 }')

if [ "$DMA_MANAGER_ADDRESS" = "$ACCOUNTB" ] \
    && [ "$DMA_RESERVE_ADDRESS" = "$ACCOUNT" ] \
    && [ "$DMA_FREEZE_ADDRESS" = "$ACCOUNT" ] \
    && [ "$DMA_CLAWBACK_ADDRESS" = "$ACCOUNT" ]; then
    echo ok
else
    date '+asset-misc asset info with diff maanger error %Y%m%d_%H%M%S'
    exit 1
fi

date '+asset-misc finish %Y%m%d_%H%M%S'
