#!/bin/bash
# This script creates some state required for Indexer testing
# TIMEOUT=400

date '+create_destroy_optin_optout start %Y%m%d_%H%M%S'

set -e
set -x
set -o pipefail
export SHELLOPTS

WALLET=$1

# Directory of this bash program
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

gcmd="goal -w ${WALLET}"

ACCOUNT=$(${gcmd} account list | awk '{ print $3 }')
ACCOUNTB=$(${gcmd} account new | awk '{ print $6 }')
${gcmd} clerk send -a 1000000 -f $ACCOUNT -t $ACCOUNTB

#############################################
# Account - create / close / create / close #
#############################################
ACCOUNT_NEW=$(${gcmd} account new | grep "Created" | awk '{ sub("\r", "", $NF); print $NF }')
${gcmd} clerk send -a 100000 -f $ACCOUNT -t $ACCOUNT_NEW
${gcmd} clerk send -a 0 -f $ACCOUNT_NEW -t $ACCOUNT -c $ACCOUNT
${gcmd} clerk send -a 100000 -f $ACCOUNT -t $ACCOUNT_NEW
${gcmd} clerk send -a 0 -f $ACCOUNT_NEW -t $ACCOUNT -c $ACCOUNT

#####################################
# Account - create / close / create #
#####################################
ACCOUNT_NEW=$(${gcmd} account new | grep "Created" | awk '{ sub("\r", "", $NF); print $NF }')
${gcmd} clerk send -a 100000 -f $ACCOUNT -t $ACCOUNT_NEW
${gcmd} clerk send -a 0 -f $ACCOUNT_NEW -t $ACCOUNT -c $ACCOUNT
${gcmd} clerk send -a 100000 -f $ACCOUNT -t $ACCOUNT_NEW

##############################
# Create an ASA, then delete #
##############################
ASSET_ID=$(${gcmd} asset create --creator ${ACCOUNT} --name cdcoin --unitname cdc --total 1337 | grep "Created" | awk '{ sub("\r", "", $NF); print $NF }')

# Asset - optin / optout / optin / optout
${gcmd} asset send --assetid $ASSET_ID -a 0 -f $ACCOUNTB -t $ACCOUNTB
${gcmd} asset send --assetid $ASSET_ID -a 0 -f $ACCOUNTB -t $ACCOUNTB -c $ACCOUNT
${gcmd} asset send --assetid $ASSET_ID -a 0 -f $ACCOUNTB -t $ACCOUNTB
${gcmd} asset send --assetid $ASSET_ID -a 0 -f $ACCOUNTB -t $ACCOUNTB -c $ACCOUNT

# Destroy the ASA
${gcmd} asset destroy --manager ${ACCOUNT} --assetid ${ASSET_ID}

################################
# Create an ASA, leave created #
################################
ASSET_ID=$(${gcmd} asset create --creator ${ACCOUNT} --name cdcoin --unitname cdc --total 1337 | grep "Created" | awk '{ sub("\r", "", $NF); print $NF }')

# Asset - optin / optout / optin
${gcmd} asset send --assetid $ASSET_ID -a 0 -f $ACCOUNTB -t $ACCOUNTB
${gcmd} asset send --assetid $ASSET_ID -a 0 -f $ACCOUNTB -t $ACCOUNTB -c $ACCOUNT
${gcmd} asset send --assetid $ASSET_ID -a 0 -f $ACCOUNTB -t $ACCOUNTB

######################################
# Create an application, then delete #
######################################
printf '#pragma version 2\nint 1' > "${TEMPDIR}/simple.teal"
APP_ID=$(${gcmd} app create --creator "${ACCOUNT}" --approval-prog "${TEMPDIR}/simple.teal" --clear-prog "${TEMPDIR}/simple.teal" --global-byteslices 1 --global-ints 1 --local-byteslices 1 --local-ints 1 | grep "Created" | awk '{ sub("\r", "", $NF); print $NF }')

# App - optin / optout / optin / optout
${gcmd} app optin --app-id $APP_ID -f ${ACCOUNTB}
${gcmd} app closeout --app-id $APP_ID -f ${ACCOUNTB}
${gcmd} app optin --app-id $APP_ID -f ${ACCOUNTB}
${gcmd} app closeout --app-id $APP_ID -f ${ACCOUNTB}

# Delete the application
${gcmd} app delete --app-id $APP_ID -f ${ACCOUNT}

########################################
# Create an application, leave created #
########################################
printf '#pragma version 2\nint 1' > "${TEMPDIR}/simple.teal"
APP_ID=$(${gcmd} app create --creator "${ACCOUNT}" --approval-prog "${TEMPDIR}/simple.teal" --clear-prog "${TEMPDIR}/simple.teal" --global-byteslices 1 --global-ints 1 --local-byteslices 1 --local-ints 1 | grep "Created" | awk '{ sub("\r", "", $NF); print $NF }')

# App - optin / optout / optin
${gcmd} app optin --app-id $APP_ID -f ${ACCOUNTB}
${gcmd} app closeout --app-id $APP_ID -f ${ACCOUNTB}
${gcmd} app optin --app-id $APP_ID -f ${ACCOUNTB}
