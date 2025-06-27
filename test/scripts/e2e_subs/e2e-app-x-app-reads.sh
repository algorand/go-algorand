#!/bin/bash

date '+app-x-app-reads-test start %Y%m%d_%H%M%S'

set -e
set -x
set -o pipefail
export SHELLOPTS

WALLET=$1

# Directory of this bash program
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

gcmd="goal -w ${WALLET}"

ACCOUNT=$(${gcmd} account list|awk '{ print $3 }')

# Create an app with global state "foo" = "xxx"
APPID=$(${gcmd} app create --creator "$ACCOUNT" --approval-prog "$DIR/tealprogs/globwrite.teal" --global-byteslices 1 --global-ints 0 --local-byteslices 0 --local-ints 0 --app-arg "str:xxx" --clear-prog <(printf '#pragma version 2\nint 1') | grep Created | awk '{ print $6 }')

# Creating an app that attempts to read APPID's global state without setting
# --foreign-app should fail
EXPERR="unavailable App 1"
RES=$(${gcmd} app create --creator "$ACCOUNT" --approval-prog "$DIR/tealprogs/xappreads.teal" --global-byteslices 0 --global-ints 0 --local-byteslices 0 --local-ints 0 --clear-prog <(printf '#pragma version 9\nint 1') 2>&1 || true)
if [[ $RES != *"$EXPERR"* ]]; then
    date '+x-app-reads FAIL expected unavailable app slot %Y%m%d_%H%M%S'
    false
fi

# Same result when using --access (even though --foreign-asset makes the slot "legal", just not an app)
RES=$(${gcmd} app create --creator "$ACCOUNT" --access --foreign-asset "$APPID" --approval-prog "$DIR/tealprogs/xappreads.teal" --global-byteslices 0 --global-ints 0 --local-byteslices 0 --local-ints 0 --clear-prog <(printf '#pragma version 9\nint 1') 2>&1 || true)
if [[ $RES != *"$EXPERR"* ]]; then
    date '+x-app-reads FAIL expected disallowed foreign global read to fail %Y%m%d_%H%M%S'
    false
fi

# Creating an app that attempts to read APPID's global state and compare with
# "bar" should make it past the foreign-app check, but fail since
# "xxx" != "bar"
EXPERR='"bar"; ==; assert'
RES=$(${gcmd} app create --creator "$ACCOUNT" --foreign-app "$APPID" --approval-prog "$DIR/tealprogs/xappreads.teal" --global-byteslices 0 --global-ints 0 --local-byteslices 0 --local-ints 0 --clear-prog <(printf '#pragma version 9\nint 1') 2>&1 || true)
if [[ $RES != *"$EXPERR"* ]]; then
    date '+x-app-reads FAIL expected foreign global mismatched read to fail %Y%m%d_%H%M%S'
    false
fi

# Same result with --access
RES=$(${gcmd} app create --creator "$ACCOUNT" --access --foreign-app "$APPID" --approval-prog "$DIR/tealprogs/xappreads.teal" --global-byteslices 0 --global-ints 0 --local-byteslices 0 --local-ints 0 --clear-prog <(printf '#pragma version 9\nint 1') 2>&1 || true)
if [[ $RES != *"$EXPERR"* ]]; then
    date '+x-app-reads FAIL expected foreign global mismatched read to fail with --access %Y%m%d_%H%M%S'
    false
fi

# Update value at "foo" to be "bar" in app $APPID
${gcmd} app call --app-id "$APPID" --from "$ACCOUNT" --app-arg "str:bar"

# Creating other app should now succeed with properly set foreignapps
${gcmd} app create --creator "$ACCOUNT" --foreign-app "$APPID" --approval-prog "$DIR/tealprogs/xappreads.teal" --global-byteslices 0 --global-ints 0 --local-byteslices 0 --local-ints 0 --clear-prog <(printf '#pragma version 9\nint 1')

# Using --access also works
${gcmd} app create --creator "$ACCOUNT" --access --foreign-app "$APPID" --approval-prog "$DIR/tealprogs/xappreads.teal" --global-byteslices 0 --global-ints 0 --local-byteslices 0 --local-ints 0 --clear-prog <(printf '#pragma version 9\nint 1')
