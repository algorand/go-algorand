#!/bin/bash

date '+app-cross-round-test start %Y%m%d_%H%M%S'

set -e
set -x
set -o pipefail
export SHELLOPTS

WALLET=$1

# Directory of this bash program
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

gcmd="goal -w ${WALLET}"

ACCOUNT=$(${gcmd} account list|awk '{ print $3 }')

printf '#pragma version 2\nint 1' > "${TEMPDIR}/int1.teal"
APPID=$(${gcmd} app create --creator ${ACCOUNT} --approval-prog ${DIR}/tealprogs/cross-round.teal --global-byteslices 1 --global-ints 1 --local-byteslices 1 --local-ints 1 --clear-prog "${TEMPDIR}/int1.teal" | grep Created | awk '{ print $6 }')

# Should succeed to opt in with first arg hello
${gcmd} app optin --app-id $APPID --from $ACCOUNT --app-arg "str:first"

# Write should now succeed
${gcmd} app call --app-id $APPID --from $ACCOUNT --app-arg "str:second"

# Write should now succeed
${gcmd} app call --app-id $APPID --from $ACCOUNT --app-arg "str:third"

# Delete application should still succeed
${gcmd} app delete --app-id $APPID --from $ACCOUNT --app-arg "str:any"

# Clear should still succeed with arbitrary args
${gcmd} app clear --app-id $APPID --from $ACCOUNT --app-arg "str:any"
