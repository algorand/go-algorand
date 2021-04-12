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

${gcmd} asset create --creator ${ACCOUNT} --name "${ASSET_NAME}" --unitname amisc --total 1000000000000

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

date '+asset-misc finish %Y%m%d_%H%M%S'
