#!/bin/bash

set -e
set -x
set -o pipefail
export SHELLOPTS

WALLET=$1

echo "NETDIR=$NETDIR"

# Directory of this bash program
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

gcmd="goal -w ${WALLET}"

ACCOUNT=$(${gcmd} account list|awk '{ print $3 }')

echo `$gcmd account list`
echo $ACCOUNT

echo `$gcmd account balance -a $ACCOUNT`

echo `$gcmd account info -a $ACCOUNT`

echo `$gcmd account export -a $ACCOUNT`

exit 1 