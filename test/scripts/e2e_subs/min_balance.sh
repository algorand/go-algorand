#!/bin/bash

set -e
set -x
set -o pipefail
export SHELLOPTS

WALLET=$1

echo "NETDIR=$NETDIR"

# Directory of this bash program
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

echo "DIR=$DIR"


gcmd="goal -w ${WALLET}"

ACCOUNT=$(${gcmd} account list|awk '{ print $3 }')

echo `$gcmd account list`
echo $ACCOUNT

echo `$gcmd account balance -a $ACCOUNT`

echo `$gcmd account info -a $ACCOUNT`

MINBAL=$(${gcmd} account info -a ${ACCOUNT}|grep 'Minimum Balance:'| awk '{ print $3 }')

echo "Minimum Balance --> $MINBAL"

EXPECTED="100000"
if [[ ${MINBAL} != ${EXPECTED} ]]; then
    date '+min_balance FAIL goal account info should return expected Minimum Ballance %Y%m%d_%H%M%S'
    false
fi

# see ./min_balance.py for more complicated scenarios
