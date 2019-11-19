#!/bin/bash

date '+dynamic-fee-teal-test start %Y%m%d_%H%M%S'

set -e
set -x
set -o pipefail
export GOPATH=$(go env GOPATH)

TEMPDIR=$(mktemp -d)
trap "rm -rf $TEMPDIR" 0

NETDIR=${TEMPDIR}/net

if [ ! -z $BINDIR ]; then
    export PATH=${BINDIR}:${PATH}
fi

goal network create -r ${NETDIR} -n dynamic-fee-teal-test -t ${GOPATH}/src/github.com/algorand/go-algorand/test/testdata/nettemplates/TwoNodes50Each.json

goal network start -r ${NETDIR}

# replaces prior trap0
trap "goal network stop -r ${NETDIR}; rm -rf ${TEMPDIR}" 0

export ALGORAND_DATA=${NETDIR}/Node

ACCOUNT=$(goal account list|awk '{ print $3 }')
ACCOUNTB=$(goal account new|awk '{ print $6 }')
ACCOUNTC=$(goal account new|awk '{ print $6 }')
ACCOUNTD=$(goal account new|awk '{ print $6 }')
ZERO_ADDRESS=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ
LEASE=uImiLf+mqOqs0BFsqIUHBh436N/z964X50e3P9Ii4ac=

# Fund ACCOUNTB
goal clerk send -a 100000000 -f ${ACCOUNT} -t ${ACCOUNTB}

# Generate the template
algotmpl -d ${GOPATH}/src/github.com/algorand/go-algorand/tools/teal/templates/ dynamic-fee --amt=1000000 --cls=${ACCOUNTC} --to=${ACCOUNTD} --fv=1 --lv=1001 --lease=${LEASE} > ${TEMPDIR}/dynamic.teal

#
# Fee will come from ACCOUNT in the first transaction
# We will close out to ACCOUNTC in second transaction
# We will pay ACCOUNTD with 1000000 microAlgos in second transaction
#

# Compile the template
goal clerk compile -a ${ACCOUNTB} -s ${TEMPDIR}/dynamic.teal -o ${TEMPDIR}/dynamic.sigteal

# Delete ACCOUNTB so that we definitely can't sign txns with it anymore
goal account delete -a ${ACCOUNTB}

# Create first transaction to spend fee (can't sign yet, no group)
goal clerk send -f ${ACCOUNT} -t ${ACCOUNTB} -a 1234 -o ${TEMPDIR}/feefund.txn

#
# First test (negative)
#

# Create second transaction mostly as per template, but pay wrong fee
goal clerk send --fee=1235 --lease=${LEASE} --firstvalid=1 --lastvalid=1001 -f ${ACCOUNTB} -a=1000000 -t=${ACCOUNTD} --close-to=${ACCOUNTC} -o ${TEMPDIR}/fundedpayment.txn

# Cat txns together
cat ${TEMPDIR}/feefund.txn ${TEMPDIR}/fundedpayment.txn > ${TEMPDIR}/group.txn

# Make a txn group, which fills in group field
goal clerk group -i ${TEMPDIR}/group.txn -o ${TEMPDIR}/txnwithgroup.txn

# Split the group
goal clerk split -i ${TEMPDIR}/txnwithgroup.txn -o ${TEMPDIR}/gtxn.txn

# Sign the fee funding transaction
goal clerk sign -i ${TEMPDIR}/gtxn-0.txn -o ${TEMPDIR}/gtxn-0.stxn

# Sign the payment transaction with logicsig
goal clerk sign -L ${TEMPDIR}/dynamic.sigteal -i ${TEMPDIR}/gtxn-1.txn -o ${TEMPDIR}/gtxn-1.stxn

# Cat signed txns together
cat ${TEMPDIR}/gtxn-0.stxn ${TEMPDIR}/gtxn-1.stxn > ${TEMPDIR}/finalgroup.stxn

# Broadcast the transaction group (should fail)
RES=$(goal clerk rawsend -f ${TEMPDIR}/finalgroup.stxn 2>&1 || true)
EXPERROR='rejected by logic'
if [[ $RES != *"${EXPERROR}"* ]]; then
    date '+dynamic-fee-teal-test FAIL txn with wrong fee should be rejected %Y%m%d_%H%M%S'
    false
fi

#
# Second test (positive)
#

# Create second transaction as per template
goal clerk send --fee=1234 --lease=${LEASE} --firstvalid=1 --lastvalid=1001 -f ${ACCOUNTB} -a=1000000 -t=${ACCOUNTD} --close-to=${ACCOUNTC} -o ${TEMPDIR}/fundedpayment.txn

# Cat txns together
cat ${TEMPDIR}/feefund.txn ${TEMPDIR}/fundedpayment.txn > ${TEMPDIR}/group.txn

# Make a txn group, which fills in group field
goal clerk group -i ${TEMPDIR}/group.txn -o ${TEMPDIR}/txnwithgroup.txn

# Split the group
goal clerk split -i ${TEMPDIR}/txnwithgroup.txn -o ${TEMPDIR}/gtxn.txn

# Sign the fee funding transaction
goal clerk sign -i ${TEMPDIR}/gtxn-0.txn -o ${TEMPDIR}/gtxn-0.stxn

# Sign the payment transaction with logicsig
goal clerk sign -L ${TEMPDIR}/dynamic.sigteal -i ${TEMPDIR}/gtxn-1.txn -o ${TEMPDIR}/gtxn-1.stxn

# Cat signed txns together
cat ${TEMPDIR}/gtxn-0.stxn ${TEMPDIR}/gtxn-1.stxn > ${TEMPDIR}/finalgroup.stxn

# Broadcast the transaction group
goal clerk rawsend -f ${TEMPDIR}/finalgroup.stxn

# Check balance of recipient
BALANCED=$(goal account balance -a ${ACCOUNTD}|awk '{ print $1 }')
if [ $BALANCED -ne 1000000 ]; then
    date '+dynamic-fee-teal-test FAIL wanted balance=1000000 but got ${BALANCED} %Y%m%d_%H%M%S'
    false
fi

date '+dynamic-fee-teal-test OK %Y%m%d_%H%M%S'
