#!/bin/bash

date '+teal-split-test start %Y%m%d_%H%M%S'

set -e
set -x
set -o pipefail
export SHELLOPTS

WALLET=$1

gcmd="goal -w ${WALLET}"

ACCOUNT=$(${gcmd} account list|awk '{ print $3 }')

ACCOUNTB=$(${gcmd} account new|awk '{ print $6 }')
ACCOUNTC=$(${gcmd} account new|awk '{ print $6 }')

sed s/TMPL_RCV1/${ACCOUNTB}/g < tools/teal/templates/split.teal.tmpl | sed s/TMPL_RCV2/${ACCOUNTC}/g | sed s/TMPL_RAT1/60/g | sed s/TMPL_RAT2/40/g | sed s/TMPL_MINPAY/100000/g | sed s/TMPL_TIMEOUT/4/g | sed s/TMPL_OWN/${ACCOUNTB}/g | sed s/TMPL_FEE/10000/g > ${TEMPDIR}/split.teal

ACCOUNT_SPLIT=$(${gcmd} clerk compile ${TEMPDIR}/split.teal -o ${TEMPDIR}/split.tealc|awk '{ print $2 }')

${gcmd} clerk send -a 60000000 -f $ACCOUNT_SPLIT -t $ACCOUNTB -o ${TEMPDIR}/b.tx
${gcmd} clerk send -a 40000000 -f $ACCOUNT_SPLIT -t $ACCOUNTC -o ${TEMPDIR}/c.tx

cat ${TEMPDIR}/b.tx ${TEMPDIR}/c.tx > ${TEMPDIR}/pregroup.tx

${gcmd} clerk group -i ${TEMPDIR}/pregroup.tx -o ${TEMPDIR}/group.tx
${gcmd} clerk split -i ${TEMPDIR}/group.tx -o ${TEMPDIR}/gx.tx
${gcmd} clerk sign -i ${TEMPDIR}/gx-0.tx -p ${TEMPDIR}/split.teal -o ${TEMPDIR}/gx-0.stx
${gcmd} clerk sign -i ${TEMPDIR}/gx-1.tx -p ${TEMPDIR}/split.teal -o ${TEMPDIR}/gx-1.stx
cat ${TEMPDIR}/gx-0.stx ${TEMPDIR}/gx-1.stx > ${TEMPDIR}/group.stx

${gcmd} clerk dryrun -t ${TEMPDIR}/group.stx

${gcmd} clerk send -a 110000000 -f ${ACCOUNT} -t ${ACCOUNT_SPLIT}

${gcmd} clerk rawsend -f ${TEMPDIR}/group.stx

BALANCEB=$(${gcmd} account balance -a ${ACCOUNTB}|awk '{ print $1 }')
BALANCEC=$(${gcmd} account balance -a ${ACCOUNTC}|awk '{ print $1 }')

if [ $BALANCEB -ne 60000000 ]; then
    echo bad balance B ${BALANCEB}
    exit 1
fi

if [ $BALANCEC -ne 40000000 ]; then
    echo bad balance B ${BALANCEC}
    exit 1
fi

# close out split account
${gcmd} clerk send -F ${TEMPDIR}/split.teal -t AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ -a 0 -c ${ACCOUNTB}

date '+teal-split-test OK %Y%m%d_%H%M%S'
