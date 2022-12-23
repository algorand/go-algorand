#!/bin/bash

scriptname="goal-app-create-state"
date "+${scriptname} start %Y%m%d_%H%M%S"

set -e
set -x
set -o pipefail
export SHELLOPTS

WALLET=$1

# Directory of this bash program
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

gcmd="goal -w ${WALLET}"

ACCOUNT=$(${gcmd} account list|awk '{ print $3 }')

printf '#pragma version 2\nint 1' > "${TEMPDIR}/simple.teal"

# Check goal flags --no-state, --no-local-state, --no-global-state
# Passing a note is needed because goal will sometimes try to customize a note
# to avoid duplicate txns

APP_CREATE_TXN_NO_STATE_FILE="${TEMPDIR}/create_no_state.txn"
${gcmd} app create --note "hello" --creator "${ACCOUNT}" --approval-prog "${TEMPDIR}/simple.teal" --clear-prog "${TEMPDIR}/simple.teal" --no-state --out "${APP_CREATE_TXN_NO_STATE_FILE}"
APP_CREATE_TXN_NO_STATE=$(msgpacktool -d < "${APP_CREATE_TXN_NO_STATE_FILE}")

FIRSTVALID=$(echo $APP_CREATE_TXN_NO_STATE | jq ".txn.fv")

APP_CREATE_TXN_NO_LOCAL_STATE_FILE="${TEMPDIR}/create_no_local_state.txn"
${gcmd} app create --note "hello" --creator "${ACCOUNT}" --approval-prog "${TEMPDIR}/simple.teal" --clear-prog "${TEMPDIR}/simple.teal" --no-local-state --global-byteslices 0 --global-ints 0 --firstvalid $FIRSTVALID --out "${APP_CREATE_TXN_NO_LOCAL_STATE_FILE}"
APP_CREATE_TXN_NO_LOCAL_STATE=$(msgpacktool -d < "${APP_CREATE_TXN_NO_LOCAL_STATE_FILE}")

if [ "$APP_CREATE_TXN_NO_LOCAL_STATE" != "$APP_CREATE_TXN_NO_STATE" ]; then
  date "+${scriptname} transactions are not equal %Y%m%d_%H%M%S"
  false
fi

APP_CREATE_TXN_NO_GLOBAL_STATE_FILE="${TEMPDIR}/create_no_global_state.txn"
${gcmd} app create --note "hello" --creator "${ACCOUNT}" --approval-prog "${TEMPDIR}/simple.teal" --clear-prog "${TEMPDIR}/simple.teal" --no-global-state --local-byteslices 0 --local-ints 0 --firstvalid $FIRSTVALID --out "${APP_CREATE_TXN_NO_GLOBAL_STATE_FILE}"
APP_CREATE_TXN_NO_GLOBAL_STATE=$(msgpacktool -d < "${APP_CREATE_TXN_NO_GLOBAL_STATE_FILE}")

if [ "$APP_CREATE_TXN_NO_GLOBAL_STATE" != "$APP_CREATE_TXN_NO_STATE" ]; then
  date "+${scriptname} transactions are not equal %Y%m%d_%H%M%S"
  false
fi

APP_CREATE_TXN_NO_FULLY_SPECIFIED_FILE="${TEMPDIR}/create_fully_specified.txn"
${gcmd} app create --note "hello" --creator "${ACCOUNT}" --approval-prog "${TEMPDIR}/simple.teal" --clear-prog "${TEMPDIR}/simple.teal" --global-byteslices 0 --global-ints 0 --local-byteslices 0 --local-ints 0 --firstvalid $FIRSTVALID --out "${APP_CREATE_TXN_NO_FULLY_SPECIFIED_FILE}"
APP_CREATE_TXN_NO_FULLY_SPECIFIED=$(msgpacktool -d < "${APP_CREATE_TXN_NO_FULLY_SPECIFIED_FILE}")

if [ "$APP_CREATE_TXN_NO_FULLY_SPECIFIED" != "$APP_CREATE_TXN_NO_STATE" ]; then
  date "+${scriptname} transactions are not equal %Y%m%d_%H%M%S"
  false
fi

date "+${scriptname} OK %Y%m%d_%H%M%S"
