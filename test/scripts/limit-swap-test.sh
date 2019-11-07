#!/bin/bash

date '+limit-swap-test start %Y%m%d_%H%M%S'

set -e
set -x

TEMPDIR=$(mktemp -d)
trap "rm -rf $TEMPDIR" 0

NETDIR=${TEMPDIR}/net

if [ ! -z $BINDIR ]; then
    export PATH=${BINDIR}:${PATH}
fi

goal network create -r ${NETDIR} -n tbd -t ${GOPATH}/src/github.com/algorand/go-algorand/test/testdata/nettemplates/TwoNodes50EachFuture.json

goal network start -r ${NETDIR}

# replaces prior trap0
trap "goal network stop -r ${NETDIR}; rm -rf ${TEMPDIR}" 0

export ALGORAND_DATA=${NETDIR}/Node

ACCOUNT=$(goal account list|awk '{ print $3 }')


goal asset create --creator ${ACCOUNT} --name bogocoin --unitname bogo --total 1000000000000

ASSET_ID=$(goal asset info --creator $ACCOUNT --asset bogo|grep 'Asset ID'|awk '{ print $3 }')

# Asset ID:         5

# quick expiration, test closeout

ROUND=$(goal node status | grep 'Last committed block:'|awk '{ print $4 }')
TIMEOUT_ROUND=$((${ROUND} + 2))

# closeout part a, Algo trader

sed s/TMPL_ASSET/${ASSET_ID}/g < ${GOPATH}/src/github.com/algorand/go-algorand/tools/teal/templates/limit-order-a.teal.tmpl | sed s/TMPL_SWAPN/31337/g | sed s/TMPL_SWAPD/137/g | sed s/TMPL_TIMEOUT/${TIMEOUT_ROUND}/g | sed s/TMPL_OWN/${ACCOUNT}/g | sed s/TMPL_FEE/100000/g | sed s/TMPL_MINTRD/10000/g > ${TEMPDIR}/limit-order-a.teal

ACCOUNT_ALGO_TRADER=$(goal clerk compile ${TEMPDIR}/limit-order-a.teal -o ${TEMPDIR}/limit-order-a.tealc|awk '{ print $2 }')

# setup trader with Algos
goal clerk send --amount 100000000 --from ${ACCOUNT} --to ${ACCOUNT_ALGO_TRADER}

goal node wait

goal clerk send -a 0 -t AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ -c ${ACCOUNT} --from-program ${TEMPDIR}/limit-order-a.teal


# closeout part b, asset trader

sed s/TMPL_ASSET/${ASSET_ID}/g < ${GOPATH}/src/github.com/algorand/go-algorand/tools/teal/templates/limit-order-b.teal.tmpl | sed s/TMPL_SWAPN/137/g | sed s/TMPL_SWAPD/31337/g | sed s/TMPL_TIMEOUT/${TIMEOUT_ROUND}/g | sed s/TMPL_OWN/${ACCOUNT}/g | sed s/TMPL_FEE/100000/g | sed s/TMPL_MINTRD/10000/g > ${TEMPDIR}/limit-order-b.teal

#goal clerk compile -n ${TEMPDIR}/limit-order-b.teal

ACCOUNT_ASSET_TRADER=$(goal clerk compile ${TEMPDIR}/limit-order-b.teal -o ${TEMPDIR}/limit-order-b.tealc|awk '{ print $2 }')

# setup trader with Algos
goal clerk send --amount 1000000 --from ${ACCOUNT} --to ${ACCOUNT_ASSET_TRADER}

# goal account balance -a $ACCOUNT_ASSET_TRADER

# make asset trader able to accept asset
goal asset send -o ${TEMPDIR}/b-asset-init.tx -a 0 --assetid ${ASSET_ID} -t $ACCOUNT_ASSET_TRADER -f $ACCOUNT_ASSET_TRADER

goal clerk sign -i ${TEMPDIR}/b-asset-init.tx -p ${TEMPDIR}/limit-order-b.teal -o ${TEMPDIR}/b-asset-init.stx

goal clerk rawsend -f ${TEMPDIR}/b-asset-init.stx

# fund account twith asset
goal asset send --assetid ${ASSET_ID} -f ${ACCOUNT} -t ${ACCOUNT_ASSET_TRADER} -a 1000000

# recover asset
goal asset send --assetid ${ASSET_ID} -t AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ -a 0 -c ${ACCOUNT} -f ${ACCOUNT_ASSET_TRADER} -o ${TEMPDIR}/bclose.tx

goal clerk sign -i ${TEMPDIR}/bclose.tx -p ${TEMPDIR}/limit-order-b.teal -o ${TEMPDIR}/bclose.stx

goal clerk rawsend -f ${TEMPDIR}/bclose.stx

# recover algos
goal clerk send -t AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ -a 0 -c ${ACCOUNT} -f ${ACCOUNT_ASSET_TRADER} -o ${TEMPDIR}/bcloseA.tx

goal clerk sign -i ${TEMPDIR}/bcloseA.tx -p ${TEMPDIR}/limit-order-b.teal -o ${TEMPDIR}/bcloseA.stx

goal clerk rawsend -f ${TEMPDIR}/bcloseA.stx

# long expiration, no closeout, actual trade

ROUND=$(goal node status | grep 'Last committed block:'|awk '{ print $4 }')
TIMEOUT_ROUND=$((${ROUND} + 200))

sed s/TMPL_ASSET/${ASSET_ID}/g < ${GOPATH}/src/github.com/algorand/go-algorand/tools/teal/templates/limit-order-b.teal.tmpl | sed s/TMPL_SWAPN/137/g | sed s/TMPL_SWAPD/31337/g | sed s/TMPL_TIMEOUT/${TIMEOUT_ROUND}/g | sed s/TMPL_OWN/${ACCOUNT}/g | sed s/TMPL_FEE/100000/g | sed s/TMPL_MINTRD/10000/g > ${TEMPDIR}/limit-order-b.teal

ACCOUNT_ASSET_TRADER=$(goal clerk compile ${TEMPDIR}/limit-order-b.teal -o ${TEMPDIR}/limit-order-b.tealc|awk '{ print $2 }')

# setup trader with Algos
goal clerk send --amount 1000000 --from ${ACCOUNT} --to ${ACCOUNT_ASSET_TRADER}

# make asset trader able to accept asset
goal asset send -o ${TEMPDIR}/b-asset-init.tx -a 0 --assetid ${ASSET_ID} -t $ACCOUNT_ASSET_TRADER -f $ACCOUNT_ASSET_TRADER

goal clerk sign -i ${TEMPDIR}/b-asset-init.tx -p ${TEMPDIR}/limit-order-b.teal -o ${TEMPDIR}/b-asset-init.stx

goal clerk rawsend -f ${TEMPDIR}/b-asset-init.stx

# fund account twith asset
goal asset send --assetid ${ASSET_ID} -f ${ACCOUNT} -t ${ACCOUNT_ASSET_TRADER} -a 100000000


# make Algo trader

sed s/TMPL_ASSET/${ASSET_ID}/g < ${GOPATH}/src/github.com/algorand/go-algorand/tools/teal/templates/limit-order-a.teal.tmpl | sed s/TMPL_SWAPN/31337/g | sed s/TMPL_SWAPD/137/g | sed s/TMPL_TIMEOUT/${TIMEOUT_ROUND}/g | sed s/TMPL_OWN/${ACCOUNT}/g | sed s/TMPL_FEE/100000/g | sed s/TMPL_MINTRD/10000/g > ${TEMPDIR}/limit-order-a.teal

ACCOUNT_ALGO_TRADER=$(goal clerk compile ${TEMPDIR}/limit-order-a.teal -o ${TEMPDIR}/limit-order-a.tealc|awk '{ print $2 }')

# setup trader with Algos
goal clerk send --amount 100000000 --from ${ACCOUNT} --to ${ACCOUNT_ALGO_TRADER}

# build trade

goal clerk send -a 137000 -f ${ACCOUNT_ALGO_TRADER} -t ${ACCOUNT} -o ${TEMPDIR}/algotrade.tx
goal asset send -a 31337000 --assetid ${ASSET_ID} -f ${ACCOUNT_ASSET_TRADER} -t ${ACCOUNT} -o ${TEMPDIR}/assettrade.tx

cat ${TEMPDIR}/algotrade.tx ${TEMPDIR}/assettrade.tx > ${TEMPDIR}/groupRaw.tx
goal clerk group -i ${TEMPDIR}/groupRaw.tx -o ${TEMPDIR}/group.tx
goal clerk split -i ${TEMPDIR}/group.tx -o ${TEMPDIR}/gx.tx

goal clerk sign -i ${TEMPDIR}/gx-0.tx -p ${TEMPDIR}/limit-order-a.teal -o ${TEMPDIR}/gx-0.stx
goal clerk sign -i ${TEMPDIR}/gx-1.tx -p ${TEMPDIR}/limit-order-b.teal -o ${TEMPDIR}/gx-1.stx

cat ${TEMPDIR}/gx-0.stx ${TEMPDIR}/gx-1.stx > ${TEMPDIR}/group.stx

goal account balance -a $ACCOUNT; goal account balance -a $ACCOUNT_ALGO_TRADER; goal account balance -a $ACCOUNT_ASSET_TRADER

# goal clerk dryrun -t ${TEMPDIR}/group.stx
goal clerk rawsend -f ${TEMPDIR}/group.stx

date '+limit-swap-test OK %Y%m%d_%H%M%S'
