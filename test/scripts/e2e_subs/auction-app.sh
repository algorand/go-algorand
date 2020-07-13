#!/usr/bin/env bash
# TIMEOUT=300

date '+auction-app start %Y%m%d_%H%M%S'

set -ex
set -o pipefail
export SHELLOPTS

WALLET=$1
gcmd="goal -w ${WALLET}"

# Directory of helper TEAL programs
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )/tealprogs"

CREATOR=$(${gcmd} account list|awk '{ print $3 }')
ALICE=$(${gcmd} account new|awk '{ print $6 }')
BOB=$(${gcmd} account new|awk '{ print $6 }')
CAROL=$(${gcmd} account new|awk '{ print $6 }')
DAVE=$(${gcmd} account new|awk '{ print $6 }')
SELLER=$(${gcmd} account new|awk '{ print $6 }')
RESERVE=$(${gcmd} account new|awk '{ print $6 }')

ZERO_ADDRESS=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ

${gcmd} clerk send -a 100000000 -f ${CREATOR} -t ${ALICE}
${gcmd} clerk send -a 100000000 -f ${CREATOR} -t ${BOB}
${gcmd} clerk send -a 100000000 -f ${CREATOR} -t ${CAROL}
${gcmd} clerk send -a 100000000 -f ${CREATOR} -t ${DAVE}
${gcmd} clerk send -a 100000000 -f ${CREATOR} -t ${SELLER}
${gcmd} clerk send -a 100000000 -f ${CREATOR} -t ${RESERVE}

APP_CREATED_STR='Created app with app index'
ERR_APP_CL_STR='only clearing out is supported for applications that do not exist'
ERR_APP_NE_STR='application does not exist'
ERR_APP_OI_STR1='has not opted in to application'
ERR_APP_OI_STR2='not opted in to app'
ERR_APP_OI_STR3='is not currently opted in'
ERR_APP_REJ_STR1='transaction rejected by ApprovalProgram'
ERR_APP_REJ_STR2='TEAL runtime encountered err opcode'
ERR_APP_REJ_STR3='- would result negative'

INIT_TRANCHES_SIZE=600000000

# create tokens
${gcmd} asset create --creator ${SELLER} --name sov --unitname sov --total $(echo "2^64 - 1" | bc)
${gcmd} asset create --creator ${RESERVE} --name usdc --unitname usdc --total $(echo "2^64 - 1" | bc)

SOV_ID=$(${gcmd} asset info --creator ${SELLER} --asset sov|grep 'Asset ID'|awk '{ print $3 }')
USDC_ID=$(${gcmd} asset info --creator ${RESERVE} --asset usdc|grep 'Asset ID'|awk '{ print $3 }')

# opt seller into reserve asset
${gcmd} asset send --from ${SELLER} --to ${SELLER} -a 0 --assetid ${USDC_ID}

# prepare escrow params
SENTINEL=0x0000000000001040
sed s/TMPL_APPID/${SENTINEL}/g < ${DIR}/sovauc_escrow.teal > ${TEMPDIR}/sovauc_escrow_tmpl.teal

${gcmd} clerk compile ${TEMPDIR}/sovauc_escrow_tmpl.teal -o ${TEMPDIR}/sovauc_escrow_tmpl.tealc
EPREFIX=$(tealcut ${TEMPDIR}/sovauc_escrow_tmpl.tealc ${SENTINEL} | grep sub0 | cut -f 2 -d ' ')
ESUFFIX=$(tealcut ${TEMPDIR}/sovauc_escrow_tmpl.tealc ${SENTINEL} b64 | grep sub1 | cut -f 2 -d ' ')
ESUFFIXH=$(tealcut ${TEMPDIR}/sovauc_escrow_tmpl.tealc ${SENTINEL} | grep hash1 | cut -f 2 -d ' ')

# create
sed s/TMPL_EPREFIX/${EPREFIX}/g < ${DIR}/sovauc_approve.teal | sed s/TMPL_ESUFFIXH/${ESUFFIXH}/g > ${TEMPDIR}/sovauc_approve.teal

LOOKBACK=1
APP_ID=$(${gcmd} app create --creator ${CREATOR} --approval-prog ${TEMPDIR}/sovauc_approve.teal --clear-prog ${DIR}/sovauc_clear.teal --global-byteslices 3 --global-ints 50 --local-byteslices 0 --local-ints 1 --app-arg addr:${SELLER} --app-arg int:${USDC_ID} --app-arg int:${SOV_ID} --app-arg int:18000000000 --app-arg int:78 --app-arg int:24000000 --app-arg int:4000 --app-arg int:${INIT_TRANCHES_SIZE} --app-arg int:${LOOKBACK} --app-arg int:1 --app-arg int:604800 --app-arg b64:${ESUFFIX} | grep "$APP_CREATED_STR" | cut -d ' ' -f 6)

# create escrow
APP_IDX=$(printf "0x%016x\n" ${APP_ID})
sed s/TMPL_APPID/${APP_IDX}/g < ${DIR}/sovauc_escrow.teal > ${TEMPDIR}/sovauc_escrow.teal
ESCROW=$(${gcmd} clerk compile ${TEMPDIR}/sovauc_escrow.teal -o ${TEMPDIR}/sovauc_escrow.tealc | cut -d ' ' -f 2)
${gcmd} clerk send -a 100000000 -f ${CREATOR} -t ${ESCROW}

# assert that escrow address matches
ESCROW_CHECK=$(tealcut ${TEMPDIR}/sovauc_escrow_tmpl.tealc ${SENTINEL} ${APP_IDX} | grep addr | cut -f 2 -d ' ')
ESCROW_COMPUTED=$(${gcmd} app read --app-id ${APP_ID} --global --guess-format | jq -r .es.tb)

if [[ $ESCROW != $ESCROW_COMPUTED ]]; then
    date "+auction-app FAIL synthetic escrow invalid $ESCROW != $ESCROW_COMPUTED %Y%m%d_%H%M%S"
    false
fi

# opt in alice, carol, dave to auction
${gcmd} app optin --app-id ${APP_ID} --from $ALICE
${gcmd} app optin --app-id ${APP_ID} --from $CAROL
${gcmd} app optin --app-id ${APP_ID} --from $DAVE

# opt in all to bid token and fund them
${gcmd} asset send -a 0 --assetid ${USDC_ID} --from ${ALICE} --to ${ALICE}
${gcmd} asset send -a 0 --assetid ${USDC_ID} --from ${BOB} --to ${BOB}
${gcmd} asset send -a 0 --assetid ${USDC_ID} --from ${CAROL} --to ${CAROL}
${gcmd} asset send -a 0 --assetid ${USDC_ID} --from ${DAVE} --to ${DAVE}
${gcmd} asset send --amount 18000000000000000 --assetid ${USDC_ID} --from ${RESERVE} --to ${ALICE}
${gcmd} asset send --amount 18000000000000000 --assetid ${USDC_ID} --from ${RESERVE} --to ${BOB}
${gcmd} asset send --amount 18000000000000000 --assetid ${USDC_ID} --from ${RESERVE} --to ${CAROL}
${gcmd} asset send --amount 18000000000000000 --assetid ${USDC_ID} --from ${RESERVE} --to ${DAVE}

# opt in alice, dave to sale token
${gcmd} asset send -a 0 --assetid ${SOV_ID} --from ${ALICE} --to ${ALICE}
${gcmd} asset send -a 0 --assetid ${SOV_ID} --from ${DAVE} --to ${DAVE}

# in loop:

#  opt in bob
${gcmd} app optin --app-id ${APP_ID} --from ${BOB}

#  start auction
${gcmd} clerk send -o ${TEMPDIR}/openr0.tx -a 100000000 -f ${CREATOR} -t ${ESCROW}
${gcmd} app call   -o ${TEMPDIR}/openr1.tx --app-id ${APP_ID} --from ${CREATOR} --app-arg int:0
${gcmd} asset send -o ${TEMPDIR}/openr2.tx -a 0 --assetid ${USDC_ID} --from ${ESCROW} --to ${ESCROW}
${gcmd} asset send -o ${TEMPDIR}/openr3.tx -a 0 --assetid ${SOV_ID} --from ${ESCROW} --to ${ESCROW}
${gcmd} asset send -o ${TEMPDIR}/openr4.tx -a ${INIT_TRANCHES_SIZE} --assetid ${SOV_ID} --from ${SELLER} --to ${ESCROW}

cat ${TEMPDIR}/openr*.tx > ${TEMPDIR}/openrc.tx
${gcmd} clerk group -i ${TEMPDIR}/openrc.tx -o ${TEMPDIR}/openrg.tx
${gcmd} clerk split -i ${TEMPDIR}/openrg.tx -o ${TEMPDIR}/openg.tx

${gcmd} clerk sign -i ${TEMPDIR}/openg-0.tx -o ${TEMPDIR}/opens0.stx
${gcmd} clerk sign -i ${TEMPDIR}/openg-1.tx -o ${TEMPDIR}/opens1.stx
${gcmd} clerk sign -i ${TEMPDIR}/openg-2.tx -o ${TEMPDIR}/opens2.stx -p ${TEMPDIR}/sovauc_escrow.teal
${gcmd} clerk sign -i ${TEMPDIR}/openg-3.tx -o ${TEMPDIR}/opens3.stx -p ${TEMPDIR}/sovauc_escrow.teal
${gcmd} clerk sign -i ${TEMPDIR}/openg-4.tx -o ${TEMPDIR}/opens4.stx

cat ${TEMPDIR}/opens*.stx > ${TEMPDIR}/open.stx
${gcmd} clerk rawsend -f ${TEMPDIR}/open.stx

#  all enter bids
# 10 000.000 000 = $10K
ABID=10000000000
BBID=20000000000
CBID=30000000000
DBID=15000000000

${gcmd} asset send -o ${TEMPDIR}/bidar0.tx -a ${ABID} --assetid ${USDC_ID} -f ${ALICE} -t ${ESCROW}
${gcmd} asset send -o ${TEMPDIR}/bidbr0.tx -a ${BBID} --assetid ${USDC_ID} -f ${BOB} -t ${ESCROW}
${gcmd} asset send -o ${TEMPDIR}/bidcr0.tx -a ${CBID} --assetid ${USDC_ID} -f ${CAROL} -t ${ESCROW}
${gcmd} asset send -o ${TEMPDIR}/biddr0.tx -a ${DBID} --assetid ${USDC_ID} -f ${DAVE} -t ${ESCROW}

${gcmd} app call -o ${TEMPDIR}/bidar1.tx --app-id ${APP_ID} --from ${ALICE}
${gcmd} app call -o ${TEMPDIR}/bidbr1.tx --app-id ${APP_ID} --from ${BOB}
${gcmd} app call -o ${TEMPDIR}/bidcr1.tx --app-id ${APP_ID} --from ${CAROL}
${gcmd} app call -o ${TEMPDIR}/biddr1.tx --app-id ${APP_ID} --from ${DAVE}

cat ${TEMPDIR}/bida*.tx > ${TEMPDIR}/bidac.tx
cat ${TEMPDIR}/bidb*.tx > ${TEMPDIR}/bidbc.tx
cat ${TEMPDIR}/bidc*.tx > ${TEMPDIR}/bidcc.tx
cat ${TEMPDIR}/bidd*.tx > ${TEMPDIR}/biddc.tx

${gcmd} clerk group -i ${TEMPDIR}/bidac.tx -o ${TEMPDIR}/bidarg.tx
${gcmd} clerk group -i ${TEMPDIR}/bidbc.tx -o ${TEMPDIR}/bidbrg.tx
${gcmd} clerk group -i ${TEMPDIR}/bidcc.tx -o ${TEMPDIR}/bidcrg.tx
${gcmd} clerk group -i ${TEMPDIR}/biddc.tx -o ${TEMPDIR}/biddrg.tx

${gcmd} clerk split -i ${TEMPDIR}/bidarg.tx -o ${TEMPDIR}/bidag.tx
${gcmd} clerk split -i ${TEMPDIR}/bidbrg.tx -o ${TEMPDIR}/bidbg.tx
${gcmd} clerk split -i ${TEMPDIR}/bidcrg.tx -o ${TEMPDIR}/bidcg.tx
${gcmd} clerk split -i ${TEMPDIR}/biddrg.tx -o ${TEMPDIR}/biddg.tx

${gcmd} clerk sign -i ${TEMPDIR}/bidag-0.tx -o ${TEMPDIR}/bidas0.stx
${gcmd} clerk sign -i ${TEMPDIR}/bidbg-0.tx -o ${TEMPDIR}/bidbs0.stx
${gcmd} clerk sign -i ${TEMPDIR}/bidcg-0.tx -o ${TEMPDIR}/bidcs0.stx
${gcmd} clerk sign -i ${TEMPDIR}/biddg-0.tx -o ${TEMPDIR}/bidds0.stx

${gcmd} clerk sign -i ${TEMPDIR}/bidag-1.tx -o ${TEMPDIR}/bidas1.stx
${gcmd} clerk sign -i ${TEMPDIR}/bidbg-1.tx -o ${TEMPDIR}/bidbs1.stx
${gcmd} clerk sign -i ${TEMPDIR}/bidcg-1.tx -o ${TEMPDIR}/bidcs1.stx
${gcmd} clerk sign -i ${TEMPDIR}/biddg-1.tx -o ${TEMPDIR}/bidds1.stx

cat ${TEMPDIR}/bidas*.stx > ${TEMPDIR}/bida.stx
cat ${TEMPDIR}/bidbs*.stx > ${TEMPDIR}/bidb.stx
cat ${TEMPDIR}/bidcs*.stx > ${TEMPDIR}/bidc.stx
cat ${TEMPDIR}/bidds*.stx > ${TEMPDIR}/bidd.stx

${gcmd} clerk rawsend -f ${TEMPDIR}/bida.stx
${gcmd} clerk rawsend -f ${TEMPDIR}/bidb.stx
${gcmd} clerk rawsend -f ${TEMPDIR}/bidc.stx
${gcmd} clerk rawsend -f ${TEMPDIR}/bidd.stx

#  clear out bob
${gcmd} app clear --from ${BOB} --app-id ${APP_ID}

#  remove bid of carol
${gcmd} app call --from ${CREATOR} --app-id ${APP_ID} --app-account ${CAROL}

#  fail to remove alice's bid TODO
RES=$(${gcmd} app call --from ${CREATOR} --app-id ${APP_ID} --app-account ${ALICE} 2>&1 || true)
if [[ $RES != *"$ERR_APP_REJ_STR1"* ]]; then
    date "+auction-app FAIL should not be able to destroy bid of valid bidder %Y%m%d_%H%M%S"
    false
fi

#  fill alice, dave bid
TRANCHE_SIZE=$(${gcmd} app read --app-id ${APP_ID} --global --guess-format | jq -r .as.ui) 
AUCTION_RAISED=$(${gcmd} app read --app-id ${APP_ID} --global --guess-format | jq -r .ar.ui)

# TODO ensure that termination for any script is correct (and avoids division by 0)
APAY=$(echo "${TRANCHE_SIZE} * ${ABID} / ${AUCTION_RAISED}" | bc)
DPAY=$(echo "${TRANCHE_SIZE} * ${DBID} / ${AUCTION_RAISED}" | bc)

AMOD=$(echo "${TRANCHE_SIZE} * ${ABID} % ${AUCTION_RAISED}" | bc)
DMOD=$(echo "${TRANCHE_SIZE} * ${DBID} % ${AUCTION_RAISED}" | bc)

${gcmd} clerk send -o ${TEMPDIR}/payar0.tx -a 1 --from ${CREATOR} --to ${ESCROW}
${gcmd} clerk send -o ${TEMPDIR}/paydr0.tx -a 1 --from ${CREATOR} --to ${ESCROW}

${gcmd} app call -o ${TEMPDIR}/payar1.tx --from ${CREATOR} --app-id ${APP_ID} --app-account ${ALICE} --app-arg int:${AMOD}
${gcmd} app call -o ${TEMPDIR}/paydr1.tx --from ${CREATOR} --app-id ${APP_ID} --app-account ${DAVE} --app-arg int:${DMOD}

${gcmd} asset send -o ${TEMPDIR}/payar2.tx --assetid ${SOV_ID} -a ${APAY} --from ${ESCROW} --to ${ALICE}
${gcmd} asset send -o ${TEMPDIR}/paydr2.tx --assetid ${SOV_ID} -a ${DPAY} --from ${ESCROW} --to ${DAVE}

cat ${TEMPDIR}/payar*.tx > ${TEMPDIR}/payac.tx
cat ${TEMPDIR}/paydr*.tx > ${TEMPDIR}/paydc.tx

${gcmd} clerk group -i ${TEMPDIR}/payac.tx -o ${TEMPDIR}/payarg.tx
${gcmd} clerk group -i ${TEMPDIR}/paydc.tx -o ${TEMPDIR}/paydrg.tx

${gcmd} clerk split -i ${TEMPDIR}/payarg.tx -o ${TEMPDIR}/payag.tx
${gcmd} clerk split -i ${TEMPDIR}/paydrg.tx -o ${TEMPDIR}/paydg.tx

${gcmd} clerk sign -i ${TEMPDIR}/payag-0.tx -o ${TEMPDIR}/payas0.stx
${gcmd} clerk sign -i ${TEMPDIR}/paydg-0.tx -o ${TEMPDIR}/payds0.stx

${gcmd} clerk sign -i ${TEMPDIR}/payag-1.tx -o ${TEMPDIR}/payas1.stx
${gcmd} clerk sign -i ${TEMPDIR}/paydg-1.tx -o ${TEMPDIR}/payds1.stx

${gcmd} clerk sign -i ${TEMPDIR}/payag-2.tx -o ${TEMPDIR}/payas2.stx -p ${TEMPDIR}/sovauc_escrow.teal
${gcmd} clerk sign -i ${TEMPDIR}/paydg-2.tx -o ${TEMPDIR}/payds2.stx -p ${TEMPDIR}/sovauc_escrow.teal

cat ${TEMPDIR}/payas*.stx > ${TEMPDIR}/paya.stx
cat ${TEMPDIR}/payds*.stx > ${TEMPDIR}/payd.stx

${gcmd} clerk rawsend -f ${TEMPDIR}/paya.stx
${gcmd} clerk rawsend -f ${TEMPDIR}/payd.stx

#  finish auction
${gcmd} clerk send -o ${TEMPDIR}/closer0.tx -a 1 --from ${CREATOR} --to ${ESCROW}
${gcmd} app call -o ${TEMPDIR}/closer1.tx --from ${CREATOR} --app-id ${APP_ID} --app-arg int:0 --app-arg int:0
${gcmd} asset send -o ${TEMPDIR}/closer2.tx --assetid ${USDC_ID} --from ${ESCROW} -c ${SELLER} -a 0 -t ${ZERO_ADDRESS}
${gcmd} asset send -o ${TEMPDIR}/closer3.tx --assetid ${SOV_ID} --from ${ESCROW} -c ${SELLER} -a 0 -t ${ZERO_ADDRESS}
${gcmd} clerk send -o ${TEMPDIR}/closer4.tx --from ${ESCROW} -c ${SELLER} -a 0 -t ${ZERO_ADDRESS}
cat ${TEMPDIR}/closer*.tx > ${TEMPDIR}/closec.tx

${gcmd} clerk group -i ${TEMPDIR}/closec.tx -o ${TEMPDIR}/closerg.tx
${gcmd} clerk split -i ${TEMPDIR}/closerg.tx -o ${TEMPDIR}/closeg.tx

${gcmd} clerk sign -i ${TEMPDIR}/closeg-0.tx -o ${TEMPDIR}/closes0.stx
${gcmd} clerk sign -i ${TEMPDIR}/closeg-1.tx -o ${TEMPDIR}/closes1.stx
${gcmd} clerk sign -i ${TEMPDIR}/closeg-2.tx -o ${TEMPDIR}/closes2.stx -p ${TEMPDIR}/sovauc_escrow.teal
${gcmd} clerk sign -i ${TEMPDIR}/closeg-3.tx -o ${TEMPDIR}/closes3.stx -p ${TEMPDIR}/sovauc_escrow.teal
${gcmd} clerk sign -i ${TEMPDIR}/closeg-4.tx -o ${TEMPDIR}/closes4.stx -p ${TEMPDIR}/sovauc_escrow.teal

cat ${TEMPDIR}/closes*.stx > ${TEMPDIR}/close.stx
${gcmd} clerk rawsend -f ${TEMPDIR}/close.stx

#  (2) start auction
rm ${TEMPDIR}/open*

RAISED_SUM=$(${gcmd} app read --app-id ${APP_ID} --global --guess-format | jq -r .u_.ui)
SUPPLY=$(${gcmd} app read --app-id ${APP_ID} --global --guess-format | jq -r .sp.ui)
SUPPLY_SCALE=$(${gcmd} app read --app-id ${APP_ID} --global --guess-format | jq -r .rs.ui)
TRANCHE_SUM=$(${gcmd} app read --app-id ${APP_ID} --global --guess-format | jq -r .t_.ui)
NUM_TRANCHES=$(${gcmd} app read --app-id ${APP_ID} --global --guess-format | jq -r .nt.ui)
ANCHOR=$(${gcmd} app read --app-id ${APP_ID} --global --guess-format | jq -r .ac.ui)

FACTOR1=$(echo "2 * ${RAISED_SUM}" | bc)
FACTOR2=$(echo "(${SUPPLY} * ${SUPPLY_SCALE}) - ${TRANCHE_SUM}" | bc)
DIVISOR=$(echo "(${LOOKBACK} * ${ANCHOR} * ${SUPPLY_SCALE}) + (${NUM_TRANCHES} * ${RAISED_SUM})" | bc)
TRANCHE_SIZE=$(echo "(${FACTOR1} * ${FACTOR2}) / ${DIVISOR}" | bc)
REM=$(echo "(${FACTOR1} * ${FACTOR2}) % ${DIVISOR}" | bc)

${gcmd} clerk send -o ${TEMPDIR}/openr0.tx -a 100000000 -f ${CREATOR} -t ${ESCROW}
${gcmd} app call   -o ${TEMPDIR}/openr1.tx --app-id ${APP_ID} --from ${CREATOR} --app-arg int:${REM}
${gcmd} asset send -o ${TEMPDIR}/openr2.tx -a 0 --assetid ${USDC_ID} --from ${ESCROW} --to ${ESCROW}
${gcmd} asset send -o ${TEMPDIR}/openr3.tx -a 0 --assetid ${SOV_ID} --from ${ESCROW} --to ${ESCROW}
${gcmd} asset send -o ${TEMPDIR}/openr4.tx -a ${TRANCHE_SIZE} --assetid ${SOV_ID} --from ${SELLER} --to ${ESCROW}

cat ${TEMPDIR}/openr*.tx > ${TEMPDIR}/openrc.tx
${gcmd} clerk group -i ${TEMPDIR}/openrc.tx -o ${TEMPDIR}/openrg.tx
${gcmd} clerk split -i ${TEMPDIR}/openrg.tx -o ${TEMPDIR}/openg.tx

${gcmd} clerk sign -i ${TEMPDIR}/openg-0.tx -o ${TEMPDIR}/opens0.stx
${gcmd} clerk sign -i ${TEMPDIR}/openg-1.tx -o ${TEMPDIR}/opens1.stx
${gcmd} clerk sign -i ${TEMPDIR}/openg-2.tx -o ${TEMPDIR}/opens2.stx -p ${TEMPDIR}/sovauc_escrow.teal
${gcmd} clerk sign -i ${TEMPDIR}/openg-3.tx -o ${TEMPDIR}/opens3.stx -p ${TEMPDIR}/sovauc_escrow.teal
${gcmd} clerk sign -i ${TEMPDIR}/openg-4.tx -o ${TEMPDIR}/opens4.stx

cat ${TEMPDIR}/opens*.stx > ${TEMPDIR}/open.stx
${gcmd} clerk rawsend -f ${TEMPDIR}/open.stx

# clean up

