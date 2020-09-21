#!/bin/bash

date '+limit-swap-test start %Y%m%d_%H%M%S'

set -e
set -x
set -o pipefail
export SHELLOPTS

WALLET=$1

gcmd="goal -w ${WALLET}"

ACCOUNT=$(${gcmd} account list|awk '{ print $3 }')
ZERO_ADDRESS=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ

${gcmd} asset create --creator ${ACCOUNT} --name bogocoin --unitname bogo --total 1000000000000

ASSET_ID=$(${gcmd} asset info --creator $ACCOUNT --unitname bogo|grep 'Asset ID'|awk '{ print $3 }')

# Asset ID:         5

echo "closeout part a, Algo trader"
# quick expiration, test closeout

ROUND=$(goal node status | grep 'Last committed block:'|awk '{ print $4 }')
TIMEOUT_ROUND=$((${ROUND} + 2))

sed s/TMPL_ASSET/${ASSET_ID}/g < ${GOPATH}/src/github.com/algorand/go-algorand/tools/teal/templates/limit-order-a.teal.tmpl | sed s/TMPL_SWAPN/31337/g | sed s/TMPL_SWAPD/137/g | sed s/TMPL_TIMEOUT/${TIMEOUT_ROUND}/g | sed s/TMPL_OWN/${ACCOUNT}/g | sed s/TMPL_FEE/100000/g | sed s/TMPL_MINTRD/10000/g > ${TEMPDIR}/limit-order-a.teal

ACCOUNT_ALGO_TRADER=$(${gcmd} clerk compile ${TEMPDIR}/limit-order-a.teal -o ${TEMPDIR}/limit-order-a.tealc|awk '{ print $2 }')

# setup trader with Algos
${gcmd} clerk send --amount 100000000 --from ${ACCOUNT} --to ${ACCOUNT_ALGO_TRADER}

goal node wait --waittime 30

${gcmd} clerk send -a 0 -t ${ZERO_ADDRESS} -c ${ACCOUNT} --from-program ${TEMPDIR}/limit-order-a.teal


echo "closeout part b, asset trader"
# quick expiration, test closeout

ROUND=$(goal node status | grep 'Last committed block:'|awk '{ print $4 }')
SETUP_ROUND=$((${ROUND} + 10))
TIMEOUT_ROUND=$((${SETUP_ROUND} + 1))

sed s/TMPL_ASSET/${ASSET_ID}/g < ${GOPATH}/src/github.com/algorand/go-algorand/tools/teal/templates/limit-order-b.teal.tmpl | sed s/TMPL_SWAPN/137/g | sed s/TMPL_SWAPD/31337/g | sed s/TMPL_TIMEOUT/${TIMEOUT_ROUND}/g | sed s/TMPL_OWN/${ACCOUNT}/g | sed s/TMPL_FEE/100000/g | sed s/TMPL_MINTRD/10000/g > ${TEMPDIR}/limit-order-b.teal


ACCOUNT_ASSET_TRADER=$(${gcmd} clerk compile ${TEMPDIR}/limit-order-b.teal -o ${TEMPDIR}/limit-order-b.tealc|awk '{ print $2 }')

echo "setup trader with Algos"
${gcmd} clerk send --amount 1000000 --from ${ACCOUNT} --to ${ACCOUNT_ASSET_TRADER} --lastvalid ${SETUP_ROUND}

# ${gcmd} account balance -a $ACCOUNT_ASSET_TRADER

echo "make asset trader able to accept asset"
ROUND=$(goal node status | grep 'Last committed block:'|awk '{ print $4 }')
${gcmd} asset send -o ${TEMPDIR}/b-asset-init.tx -a 0 --assetid ${ASSET_ID} -t $ACCOUNT_ASSET_TRADER -f $ACCOUNT_ASSET_TRADER --validrounds $((${SETUP_ROUND} - ${ROUND} - 1))

${gcmd} clerk sign -i ${TEMPDIR}/b-asset-init.tx -p ${TEMPDIR}/limit-order-b.teal -o ${TEMPDIR}/b-asset-init.stx

${gcmd} clerk rawsend -f ${TEMPDIR}/b-asset-init.stx

echo "fund account with asset"
${gcmd} asset send --assetid ${ASSET_ID} -f ${ACCOUNT} -t ${ACCOUNT_ASSET_TRADER} -a 1000000

ROUND=$(goal node status | grep 'Last committed block:'|awk '{ print $4 }')
while [ $ROUND -lt $TIMEOUT_ROUND ]; do
    goal node wait --waittime 30
    ROUND=$(goal node status | grep 'Last committed block:'|awk '{ print $4 }')
done

echo "recover asset"
${gcmd} asset send --assetid ${ASSET_ID} -t ${ZERO_ADDRESS} -a 0 -c ${ACCOUNT} -f ${ACCOUNT_ASSET_TRADER} -o ${TEMPDIR}/bclose.tx

${gcmd} clerk sign -i ${TEMPDIR}/bclose.tx -p ${TEMPDIR}/limit-order-b.teal -o ${TEMPDIR}/bclose.stx

${gcmd} clerk rawsend -f ${TEMPDIR}/bclose.stx

echo "recover algos"
${gcmd} clerk send -t ${ZERO_ADDRESS} -a 0 -c ${ACCOUNT} -f ${ACCOUNT_ASSET_TRADER} -o ${TEMPDIR}/bcloseA.tx

${gcmd} clerk sign -i ${TEMPDIR}/bcloseA.tx -p ${TEMPDIR}/limit-order-b.teal -o ${TEMPDIR}/bcloseA.stx

${gcmd} clerk rawsend -f ${TEMPDIR}/bcloseA.stx

# long expiration, no closeout, actual trade
echo "test actual swap"

ROUND=$(goal node status | grep 'Last committed block:'|awk '{ print $4 }')

SETUP_ROUND=$((${ROUND} + 199))
TIMEOUT_ROUND=$((${SETUP_ROUND} + 1))

sed s/TMPL_ASSET/${ASSET_ID}/g < ${GOPATH}/src/github.com/algorand/go-algorand/tools/teal/templates/limit-order-b.teal.tmpl | sed s/TMPL_SWAPN/137/g | sed s/TMPL_SWAPD/31337/g | sed s/TMPL_TIMEOUT/${TIMEOUT_ROUND}/g | sed s/TMPL_OWN/${ACCOUNT}/g | sed s/TMPL_FEE/100000/g | sed s/TMPL_MINTRD/10000/g > ${TEMPDIR}/limit-order-b.teal

ACCOUNT_ASSET_TRADER=$(${gcmd} clerk compile ${TEMPDIR}/limit-order-b.teal -o ${TEMPDIR}/limit-order-b.tealc|awk '{ print $2 }')

echo "setup trader with Algos"
${gcmd} clerk send --amount 1000000 --from ${ACCOUNT} --to ${ACCOUNT_ASSET_TRADER}

echo "make asset trader able to accept asset"
ROUND=$(goal node status | grep 'Last committed block:'|awk '{ print $4 }')
${gcmd} asset send -o ${TEMPDIR}/b-asset-init.tx -a 0 --assetid ${ASSET_ID} -t $ACCOUNT_ASSET_TRADER -f $ACCOUNT_ASSET_TRADER --validrounds $((${SETUP_ROUND} - ${ROUND} - 1))

${gcmd} clerk sign -i ${TEMPDIR}/b-asset-init.tx -p ${TEMPDIR}/limit-order-b.teal -o ${TEMPDIR}/b-asset-init.stx

${gcmd} clerk rawsend -f ${TEMPDIR}/b-asset-init.stx

echo "fund account with asset"
${gcmd} asset send --assetid ${ASSET_ID} -f ${ACCOUNT} -t ${ACCOUNT_ASSET_TRADER} -a 100000000


echo "make Algo trader"

sed s/TMPL_ASSET/${ASSET_ID}/g < ${GOPATH}/src/github.com/algorand/go-algorand/tools/teal/templates/limit-order-a.teal.tmpl | sed s/TMPL_SWAPN/31337/g | sed s/TMPL_SWAPD/137/g | sed s/TMPL_TIMEOUT/${TIMEOUT_ROUND}/g | sed s/TMPL_OWN/${ACCOUNT}/g | sed s/TMPL_FEE/100000/g | sed s/TMPL_MINTRD/10000/g > ${TEMPDIR}/limit-order-a.teal

ACCOUNT_ALGO_TRADER=$(${gcmd} clerk compile ${TEMPDIR}/limit-order-a.teal -o ${TEMPDIR}/limit-order-a.tealc|awk '{ print $2 }')

echo "setup trader with Algos"
${gcmd} clerk send --amount 100000000 --from ${ACCOUNT} --to ${ACCOUNT_ALGO_TRADER}

echo "build trade"

${gcmd} clerk send -a 137000 -f ${ACCOUNT_ALGO_TRADER} -t ${ACCOUNT} -o ${TEMPDIR}/algotrade.tx
${gcmd} asset send -a 31337000 --assetid ${ASSET_ID} -f ${ACCOUNT_ASSET_TRADER} -t ${ACCOUNT} -o ${TEMPDIR}/assettrade.tx

cat ${TEMPDIR}/algotrade.tx ${TEMPDIR}/assettrade.tx > ${TEMPDIR}/groupRaw.tx
${gcmd} clerk group -i ${TEMPDIR}/groupRaw.tx -o ${TEMPDIR}/group.tx
${gcmd} clerk split -i ${TEMPDIR}/group.tx -o ${TEMPDIR}/gx.tx

${gcmd} clerk sign -i ${TEMPDIR}/gx-0.tx -p ${TEMPDIR}/limit-order-a.teal -o ${TEMPDIR}/gx-0.stx
${gcmd} clerk sign -i ${TEMPDIR}/gx-1.tx -p ${TEMPDIR}/limit-order-b.teal -o ${TEMPDIR}/gx-1.stx

cat ${TEMPDIR}/gx-0.stx ${TEMPDIR}/gx-1.stx > ${TEMPDIR}/group.stx

${gcmd} account balance -a $ACCOUNT; ${gcmd} account balance -a $ACCOUNT_ALGO_TRADER; ${gcmd} account balance -a $ACCOUNT_ASSET_TRADER

${gcmd} clerk dryrun -t ${TEMPDIR}/group.stx
${gcmd} clerk rawsend -f ${TEMPDIR}/group.stx

date '+limit-swap-test OK %Y%m%d_%H%M%S'
