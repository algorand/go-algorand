#!/bin/bash

date '+app-abi-arg-test start %Y%m%d_%H%M%S'

set -e
set -x
set -o pipefail
export SHELLOPTS

WALLET=$1

# Directory of this bash program
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

gcmd="goal -w ${WALLET}"

GLOBAL_INTS=2
ACCOUNT=$(${gcmd} account list|awk '{ print $3 }')

printf '#pragma version 2\nint 1' > "${TEMPDIR}/simple.teal"
PROGRAM=($(${gcmd} clerk compile "${TEMPDIR}/simple.teal"))
APPID=$(${gcmd} app create --creator ${ACCOUNT} --approval-prog ${DIR}/tealprogs/app-abi-arg.teal --clear-prog ${TEMPDIR}/simple.teal --global-ints ${GLOBAL_INTS} | grep Created | awk '{ print $6 }')

# Should succeed to opt in with string "optin"
${gcmd} app optin --app-id $APPID --from $ACCOUNT --app-arg 'abi:string:"optin"'

# Call should now succeed
${gcmd} app call --app-id $APPID --from $ACCOUNT --app-arg 'abi:uint64:0'
${gcmd} app call --app-id $APPID --from $ACCOUNT --app-arg 'abi:byte[3]:"AAEC"'
${gcmd} app call --app-id $APPID --from $ACCOUNT --app-arg 'abi:(string,(byte[3],ufixed64x3)):["uwu",["AAEC",12.34]]'
${gcmd} app call --app-id $APPID --from $ACCOUNT --app-arg 'abi:(uint64,string,bool[]):[399,"should pass",[true,false,false,true]]'

# Delete application should still succeed
${gcmd} app delete --app-id $APPID --from $ACCOUNT

# Clear should still succeed
${gcmd} app clear --app-id $APPID --from $ACCOUNT
