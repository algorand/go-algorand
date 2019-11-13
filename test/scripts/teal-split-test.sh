#!/bin/bash

date '+teal-split-test start %Y%m%d_%H%M%S'

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

ACCOUNTB=$(goal account new|awk '{ print $6 }')
ACCOUNTC=$(goal account new|awk '{ print $6 }')

sed s/TMPL_RCV1/${ACCOUNTB}/g < ${GOPATH}/src/github.com/algorand/go-algorand/tools/teal/templates/split.teal.tmpl | sed s/TMPL_RCV2/${ACCOUNTC}/g | sed s/TMPL_RATN/60/g | sed s/TMPL_RATD/40/g | sed s/TMPL_MINPAY/100000/g | sed s/TMPL_TIMEOUT/4/g | sed s/TMPL_OWN/${ACCOUNTB}/g | sed s/TMPL_FEE/10000/g > ${TEMPDIR}/split.teal

ACCOUNT_SPLIT=$(goal clerk compile ${TEMPDIR}/split.teal -o ${TEMPDIR}/split.tealc|awk '{ print $2 }')

goal clerk send -a 60000000 -f $ACCOUNT_SPLIT -t $ACCOUNTB -o ${TEMPDIR}/b.tx
goal clerk send -a 40000000 -f $ACCOUNT_SPLIT -t $ACCOUNTC -o ${TEMPDIR}/c.tx

cat ${TEMPDIR}/b.tx ${TEMPDIR}/c.tx > ${TEMPDIR}/pregroup.tx

goal clerk group -i ${TEMPDIR}/pregroup.tx -o ${TEMPDIR}/group.tx
goal clerk split -i ${TEMPDIR}/group.tx -o ${TEMPDIR}/gx.tx
goal clerk sign -i ${TEMPDIR}/gx-0.tx -p ${TEMPDIR}/split.teal -o ${TEMPDIR}/gx-0.stx
goal clerk sign -i ${TEMPDIR}/gx-1.tx -p ${TEMPDIR}/split.teal -o ${TEMPDIR}/gx-1.stx
cat ${TEMPDIR}/gx-0.stx ${TEMPDIR}/gx-1.stx > ${TEMPDIR}/group.stx

goal clerk dryrun -t ${TEMPDIR}/group.stx

goal clerk send -a 110000000 -f ${ACCOUNT} -t ${ACCOUNT_SPLIT}

goal clerk rawsend -f ${TEMPDIR}/group.stx

BALANCEB=$(goal account balance -a ${ACCOUNTB}|awk '{ print $1 }')
BALANCEC=$(goal account balance -a ${ACCOUNTC}|awk '{ print $1 }')

if [ $BALANCEB -ne 60000000 ]; then
    echo bad balance B ${BALANCEB}
    exit 1
fi

if [ $BALANCEC -ne 40000000 ]; then
    echo bad balance B ${BALANCEC}
    exit 1
fi

# close out split account
goal clerk send -F ${TEMPDIR}/split.teal -t AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ -a 0 -c ${ACCOUNTB}

date '+teal-split-test OK %Y%m%d_%H%M%S'
