#!/bin/bash

date '+periodic-teal-test start %Y%m%d_%H%M%S'

set -e
set -x
set -o pipefail
export SHELLOPTS

WALLET=$1

gcmd="goal -w ${WALLET}"

ACCOUNT=$(${gcmd} account list|awk '{ print $3 }')
ACCOUNTB=$(${gcmd} account new|awk '{ print $6 }')
ZERO_ADDRESS=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ
LEASE=YmxhaCBibGFoIGxlYXNlIHdoYXRldmVyIGJsYWghISE=

sed s/TMPL_RCV/${ACCOUNTB}/g < tools/teal/templates/periodic-payment-escrow.teal.tmpl | sed s/TMPL_PERIOD/5/g | sed s/TMPL_DUR/2/g | sed s/TMPL_AMT/100000/g | sed s/TMPL_LEASE/${LEASE}/g | sed s/TMPL_TIMEOUT/16/g | sed s/TMPL_FEE/10000/g > ${TEMPDIR}/periodic.teal

ACCOUNT_PERIODIC=$(${gcmd} clerk compile ${TEMPDIR}/periodic.teal -o ${TEMPDIR}/periodic.tealc|awk '{ print $2 }')

ROUND=5
DUR_ROUND=$((${ROUND} + 2))
${gcmd} clerk send -a 100000 -t ${ACCOUNTB} --from-program ${TEMPDIR}/periodic.teal --firstvalid ${ROUND} --lastvalid ${DUR_ROUND} -x ${LEASE} -o ${TEMPDIR}/a.tx
${gcmd} clerk dryrun -t ${TEMPDIR}/a.tx

${gcmd} clerk send -a 1000000000 -f ${ACCOUNT} -t ${ACCOUNT_PERIODIC}

trycount=0
sendcount=0

while [ $sendcount -lt 3 ]; do
    trycount=$(($trycount + 1))
    if [ $trycount -gt 100 ]; then
	date '+periodic-teal-test FAIL too many tries %Y%m%d_%H%M%S'
	false
    fi
    ROUND=$(goal node status | grep 'Last committed block:'|awk '{ print $4 }')
    DUR_ROUND=$((${ROUND} + 2))
    if ${gcmd} clerk send -a 100000 -t ${ACCOUNTB} --from-program ${TEMPDIR}/periodic.teal --firstvalid ${ROUND} --lastvalid ${DUR_ROUND} -x ${LEASE}; then
	sendcount=$(($sendcount + 1))
	date '+periodic-teal-test sent one at ${ROUND} %Y%m%d_%H%M%S'
    fi
    sleep 2
done

BALANCEB=$(${gcmd} account balance -a ${ACCOUNTB}|awk '{ print $1 }')

if [ $BALANCEB -ne 300000 ]; then
    date '+periodic-teal-test FAIL wanted balance=3000000 but got ${BALANCEB} %Y%m%d_%H%M%S'
    false
fi

ROUND=25
DUR_ROUND=$((${ROUND} + 2))
${gcmd} clerk send -a 0 -t ${ZERO_ADDRESS} -c ${ACCOUNTB} --from-program ${TEMPDIR}/periodic.teal --firstvalid ${ROUND} --lastvalid ${DUR_ROUND} -x ${LEASE} -o ${TEMPDIR}/a.tx
${gcmd} clerk dryrun -t ${TEMPDIR}/a.tx

trycount=0
sendcount=0
while [ $sendcount -lt 1 ]; do
    trycount=$(($trycount + 1))
    if [ $trycount -gt 30 ]; then
	date '+periodic-teal-test FAIL too many close tries %Y%m%d_%H%M%S'
	false
    fi
    ROUND=$(goal node status | grep 'Last committed block:'|awk '{ print $4 }')
    DUR_ROUND=$((${ROUND} + 2))
    if ${gcmd} clerk send -a 0 -t ${ZERO_ADDRESS} -c ${ACCOUNTB} --from-program ${TEMPDIR}/periodic.teal --firstvalid ${ROUND} --lastvalid ${DUR_ROUND} -x ${LEASE}; then
	sendcount=$(($sendcount + 1))
	date '+periodic-teal-test sent one at ${ROUND} %Y%m%d_%H%M%S'
    fi
    sleep 2
done

date '+periodic-teal-test OK %Y%m%d_%H%M%S'
