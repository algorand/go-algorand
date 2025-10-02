#!/bin/bash

filename=$(basename "$0")
scriptname="${filename%.*}"
date "+${scriptname} start %Y%m%d_%H%M%S"

set -ex
set -o pipefail
export SHELLOPTS

WALLET=$1
gcmd="goal -w ${WALLET}"

ACCOUNT=$(${gcmd} account list|awk '{ print $3 }')
ACCOUNTB=$(${gcmd} account new|awk '{ print $6 }')
ACCOUNTC=$(${gcmd} account new|awk '{ print $6 }')
ACCOUNTD=$(${gcmd} account new|awk '{ print $6 }')
ACCOUNTE=$(${gcmd} account new|awk '{ print $6 }')

# X will be rekeyed to Y, so we can test goal asset <op> -S ...
ACCOUNTX=$(${gcmd} account new|awk '{ print $6 }')
ACCOUNTY=$(${gcmd} account new|awk '{ print $6 }')

ASSET_NAME='Birlot : décollage vs. ࠶🦪'

# to ensure IPFS URLs longer than 32 characters are supported
ASSET_URL="/ipfs/QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco/wiki/Verifiable_random_function.html"

${gcmd} asset create --creator "${ACCOUNT}" --name "${ASSET_NAME}" --unitname amisc --total 1000000000000 --asseturl "${ASSET_URL}"

ASSET_ID=$(${gcmd} asset info --creator $ACCOUNT --unitname amisc|grep 'Asset ID'|awk '{ print $3 }')

${gcmd} clerk send --from ${ACCOUNT} --to ${ACCOUNTB} --amount 1000000
${gcmd} clerk send --from ${ACCOUNT} --to ${ACCOUNTC} --amount 1000000
${gcmd} clerk send --from ${ACCOUNT} --to ${ACCOUNTD} --amount 1000000
${gcmd} clerk send --from ${ACCOUNT} --to ${ACCOUNTX} --amount 1000000
${gcmd} clerk send --from ${ACCOUNTX} --to ${ACCOUNTX} --amount 0 --rekey-to ${ACCOUNTY}

# opt in to asset
${gcmd} asset optin --assetid ${ASSET_ID} -a ${ACCOUNTB}
${gcmd} asset optin --assetid ${ASSET_ID} -a ${ACCOUNTC}
${gcmd} asset optin --assetid ${ASSET_ID} -a ${ACCOUNTD}
${gcmd} asset optin --assetid ${ASSET_ID} -a ${ACCOUNTX} -S ${ACCOUNTY}

# fund asset
${gcmd} asset send --assetid ${ASSET_ID} -f ${ACCOUNT} -t ${ACCOUNTB} -a 1000

# fund asset to rekeyed account, then return it
${gcmd} asset send --assetid ${ASSET_ID} -f ${ACCOUNT} -t ${ACCOUNTX} -a 500
${gcmd} asset send --assetid ${ASSET_ID} -f ${ACCOUNTX} -S ${ACCOUNTY} -t ${ACCOUNT} -a 500

# asset send some and close the rest
${gcmd} asset send --assetid ${ASSET_ID} -f ${ACCOUNTB} -t ${ACCOUNTC} -a 100 --close-to ${ACCOUNTD}

if ${gcmd} account info -a ${ACCOUNTC} |grep "${ASSET_NAME}"|grep -c -q 'balance 100 '; then
    echo ok
else
    date "+${scriptname} asset balance error %Y%m%d_%H%M%S"
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
    date "+${scriptname} asset manager, reserve, freezer, and clawback should be creator error %Y%m%d_%H%M%S"
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
    date "+${scriptname} immutable asset manager/reserve/freezer/clawback addresses error %Y%m%d_%H%M%S"
    exit 1
fi

# case 3: asset created with manager, reserve, freezer, and clawback different from the creator
${gcmd} asset create --creator "${ACCOUNT}" --manager "${ACCOUNTB}" --reserve "${ACCOUNTC}" --freezer "${ACCOUNTD}" --clawback "${ACCOUNTE}" --name "${ASSET_NAME}" --unitname dma --total 1000000000000 --asseturl "${ASSET_URL}"

# case 3a: asset info should fail if reserve address has not opted into the asset.
EXPERROR='account asset info not found'
RES=$(${gcmd} asset info --creator $ACCOUNT --unitname dma 2>&1 || true)
if [[ $RES != *"${EXPERROR}"* ]]; then
    date "+${scriptname} FAIL asset info should fail unless reserve account was opted in %Y%m%d_%H%M%S"
    exit 1
else
    echo ok
fi

# case 3b: Reserve address opts into the the asset, and gets asset info successfully.
${gcmd} asset optin --creator "${ACCOUNT}" --asset dma --account ${ACCOUNTC}
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
    date "+${scriptname} asset addresses with diff manager/reserve/freeze/clawback error %Y%m%d_%H%M%S"
    exit 1
fi

# Test Scenario - check if asset is created successfully when passed in different combination of flags for addresses
# case 1: create asset with both manager flag and no-manager flag
if ${gcmd} asset create --creator "${ACCOUNT}" --no-manager --manager "${ACCOUNTB}" --name "${ASSET_NAME}" --unitname errmisc --total 1000000000000 --asseturl "${ASSET_URL}"; then
    date "+${scriptname} asset with --manager and --no-manager flags created successfully error %Y%m%d_%H%M%S"
    exit 1
else
    echo "Expected. Cannot create asset with both manager flag and no-manager flag"
fi

# case 2: create asset with both reserve flag and no-reserve flag
if ${gcmd} asset create --creator "${ACCOUNT}" --no-reserve --reserve "${ACCOUNTC}" --name "${ASSET_NAME}" --unitname errmisc --total 1000000000000 --asseturl "${ASSET_URL}"; then
    date "+${scriptname} asset with --reserve and --no-reserve flags created successfully error %Y%m%d_%H%M%S"
    exit 1
else
    echo "Expected. Cannot create asset with both reserve flag and no-reserve flag"
fi

# case 3: create asset with both freezer flag and no-freezer flag
if ${gcmd} asset create --creator "${ACCOUNT}" --no-freezer --freezer "${ACCOUNTD}" --name "${ASSET_NAME}" --unitname errmisc --total 1000000000000 --asseturl "${ASSET_URL}"; then
    date "+${scriptname} asset with --freezer and --no-freezer flags created successfully error %Y%m%d_%H%M%S"
    exit 1
else
    echo "Expected. Cannot create asset with both freezer flag and no-freezer flag"
fi

# case 4: create asset with both clawback flag and no-clawback flag
if ${gcmd} asset create --creator "${ACCOUNT}" --no-clawback --clawback "${ACCOUNTE}" --name "${ASSET_NAME}" --unitname errmisc --total 1000000000000 --asseturl "${ASSET_URL}"; then
    date "+${scriptname} asset with --clawback and --no-clawback flags created successfully error %Y%m%d_%H%M%S"
    exit 1
else
    echo "Expected. Cannot create asset with both clawback flag and no-clawback flag"
fi

# case 5: create asset with reserve flag, no-freezer flag and no-clawback flag
if ${gcmd} asset create --creator "${ACCOUNT}" --no-freezer --no-clawback --reserve "${ACCOUNTE}" --name "${ASSET_NAME}" --unitname errmisc --total 1000000000000 --asseturl "${ASSET_URL}"; then
    echo "ok"
else
    date "+${scriptname} asset with independent flags created unsuccessfully error %Y%m%d_%H%M%S"
    exit 1
fi

# case 6: create and destroy with a rekeyed account
if ${gcmd} asset create --creator "${ACCOUNTX}" -S "${ACCOUNTY}" --name "${ASSET_NAME}" --unitname rkeymisc --total 10 --asseturl "${ASSET_URL}"; then
    echo "ok"
else
    date "+${scriptname} rekeyed account unable to create asset %Y%m%d_%H%M%S"
    exit 1
fi
ASSET_ID=$(${gcmd} asset info --creator ${ACCOUNTX} --unitname rkeymisc|grep 'Asset ID'|awk '{ print $3 }')
if ${gcmd} asset destroy --creator "${ACCOUNTX}" -S "${ACCOUNTY}" --assetid $ASSET_ID; then
    echo "ok"
else
    date "+${scriptname} rekeyed account unable to destroy asset %Y%m%d_%H%M%S"
    exit 1
fi

# Test Scenario - check transferring of the 0 asset
# case 1: send 0 units of 0 asset to self should fail
EXPERROR='asset 0 does not exist or has been deleted'
RES=$(${gcmd} asset send --from "${ACCOUNT}" --to "${ACCOUNT}" --assetid 0 --amount 0 2>&1 || true)
if [[ $RES != *"${EXPERROR}"* ]]; then
  date "+${scriptname} FAIL asset transfer of 0 units of 0 asset should not be allowed to self in %Y%m%d_%H%M%S"
  exit 1
else
  echo ok
fi

# case 2: send 0 units of 0 asset to someone else should succeed
${gcmd} asset send --from "${ACCOUNT}" --to "${ACCOUNTB}" --assetid 0 --amount 0

# case 3: send 0 units of 0 asset to someone else including a close-to should fail
EXPERROR='asset 0 not present in account'
RES=$(${gcmd} asset send --from "${ACCOUNT}" --to "${ACCOUNTB}" --assetid 0 --amount 0 --close-to "${ACCOUNTB}" 2>&1 || true)
if [[ $RES != *"${EXPERROR}"* ]]; then
  date "+${scriptname} FAIL asset transfer of 0 units of 0 asset including a close-to should not be allowed in %Y%m%d_%H%M%S"
  exit 1
else
  echo ok
fi

date "+$scriptname OK %Y%m%d_%H%M%S"
