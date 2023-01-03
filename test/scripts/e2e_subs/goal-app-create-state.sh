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

APP_CREATE_TXN_NO_STATE_FILE="${TEMPDIR}/create_no_state.txn"
APP_CREATE_TXN_NO_GLOBAL_STATE_FILE="${TEMPDIR}/create_no_global_state.txn"
APP_CREATE_TXN_NO_LOCAL_STATE_FILE="${TEMPDIR}/create_no_local_state.txn"
APP_CREATE_TXN_NO_FULLY_SPECIFIED_FILE="${TEMPDIR}/create_fully_specified.txn"

# Checks for 'goal app create'

# Passing a note is needed because goal will sometimes try to customize a note
# to avoid duplicate txns

${gcmd} app create --note "hello" --creator "${ACCOUNT}" --approval-prog "${TEMPDIR}/simple.teal" --clear-prog "${TEMPDIR}/simple.teal" --no-state --out "${APP_CREATE_TXN_NO_STATE_FILE}"
APP_CREATE_TXN_NO_STATE=$(msgpacktool -d < "${APP_CREATE_TXN_NO_STATE_FILE}")

FIRSTVALID=$(echo $APP_CREATE_TXN_NO_STATE | jq ".txn.fv")

# Passing --firstvalid is used for subsequent transactions to ensure they have
# the same valid range as the first txn

${gcmd} app create --note "hello" --creator "${ACCOUNT}" --approval-prog "${TEMPDIR}/simple.teal" --clear-prog "${TEMPDIR}/simple.teal" --no-local-state --global-byteslices 0 --global-ints 0 --firstvalid $FIRSTVALID --out "${APP_CREATE_TXN_NO_LOCAL_STATE_FILE}"
APP_CREATE_TXN_NO_LOCAL_STATE=$(msgpacktool -d < "${APP_CREATE_TXN_NO_LOCAL_STATE_FILE}")

if [ "$APP_CREATE_TXN_NO_LOCAL_STATE" != "$APP_CREATE_TXN_NO_STATE" ]; then
  date "+${scriptname} transactions made with 'goal app create' are not equal (A) %Y%m%d_%H%M%S"
  false
fi

${gcmd} app create --note "hello" --creator "${ACCOUNT}" --approval-prog "${TEMPDIR}/simple.teal" --clear-prog "${TEMPDIR}/simple.teal" --no-global-state --local-byteslices 0 --local-ints 0 --firstvalid $FIRSTVALID --out "${APP_CREATE_TXN_NO_GLOBAL_STATE_FILE}"
APP_CREATE_TXN_NO_GLOBAL_STATE=$(msgpacktool -d < "${APP_CREATE_TXN_NO_GLOBAL_STATE_FILE}")

if [ "$APP_CREATE_TXN_NO_GLOBAL_STATE" != "$APP_CREATE_TXN_NO_STATE" ]; then
  date "+${scriptname} transactions made with 'goal app create' are not equal (B) %Y%m%d_%H%M%S"
  false
fi

${gcmd} app create --note "hello" --creator "${ACCOUNT}" --approval-prog "${TEMPDIR}/simple.teal" --clear-prog "${TEMPDIR}/simple.teal" --global-byteslices 0 --global-ints 0 --local-byteslices 0 --local-ints 0 --firstvalid $FIRSTVALID --out "${APP_CREATE_TXN_NO_FULLY_SPECIFIED_FILE}"
APP_CREATE_TXN_NO_FULLY_SPECIFIED=$(msgpacktool -d < "${APP_CREATE_TXN_NO_FULLY_SPECIFIED_FILE}")

if [ "$APP_CREATE_TXN_NO_FULLY_SPECIFIED" != "$APP_CREATE_TXN_NO_STATE" ]; then
  date "+${scriptname} transactions made with 'goal app create' are not equal (C) %Y%m%d_%H%M%S"
  false
fi

# Checks for 'goal method --create'

${gcmd} app method --create --note "hello" --from "${ACCOUNT}" --method "create(uint64)uint64" --arg "1234" --create --approval-prog "${TEMPDIR}/simple.teal" --clear-prog "${TEMPDIR}/simple.teal" --no-state --out "${APP_CREATE_TXN_NO_STATE_FILE}"
APP_CREATE_TXN_NO_STATE=$(msgpacktool -d < "${APP_CREATE_TXN_NO_STATE_FILE}")

FIRSTVALID=$(echo $APP_CREATE_TXN_NO_STATE | jq ".txn.fv")

${gcmd} app method --create --note "hello" --from "${ACCOUNT}" --method "create(uint64)uint64" --arg "1234" --create --approval-prog "${TEMPDIR}/simple.teal" --clear-prog "${TEMPDIR}/simple.teal" --no-local-state --global-byteslices 0 --global-ints 0 --firstvalid $FIRSTVALID --out "${APP_CREATE_TXN_NO_LOCAL_STATE_FILE}"
APP_CREATE_TXN_NO_LOCAL_STATE=$(msgpacktool -d < "${APP_CREATE_TXN_NO_LOCAL_STATE_FILE}")

if [ "$APP_CREATE_TXN_NO_LOCAL_STATE" != "$APP_CREATE_TXN_NO_STATE" ]; then
  date "+${scriptname} transactions made with 'goal method --create' are not equal (A) %Y%m%d_%H%M%S"
  false
fi

${gcmd} app method --create --note "hello" --from "${ACCOUNT}" --method "create(uint64)uint64" --arg "1234" --create --approval-prog "${TEMPDIR}/simple.teal" --clear-prog "${TEMPDIR}/simple.teal" --no-global-state --local-byteslices 0 --local-ints 0 --firstvalid $FIRSTVALID --out "${APP_CREATE_TXN_NO_GLOBAL_STATE_FILE}"
APP_CREATE_TXN_NO_GLOBAL_STATE=$(msgpacktool -d < "${APP_CREATE_TXN_NO_GLOBAL_STATE_FILE}")

if [ "$APP_CREATE_TXN_NO_GLOBAL_STATE" != "$APP_CREATE_TXN_NO_STATE" ]; then
  date "+${scriptname} transactions made with 'goal method --create' are not equal (B) %Y%m%d_%H%M%S"
  false
fi

${gcmd} app method --create --note "hello" --from "${ACCOUNT}" --method "create(uint64)uint64" --arg "1234" --create --approval-prog "${TEMPDIR}/simple.teal" --clear-prog "${TEMPDIR}/simple.teal" --global-byteslices 0 --global-ints 0 --local-byteslices 0 --local-ints 0 --firstvalid $FIRSTVALID --out "${APP_CREATE_TXN_NO_FULLY_SPECIFIED_FILE}"
APP_CREATE_TXN_NO_FULLY_SPECIFIED=$(msgpacktool -d < "${APP_CREATE_TXN_NO_FULLY_SPECIFIED_FILE}")

if [ "$APP_CREATE_TXN_NO_FULLY_SPECIFIED" != "$APP_CREATE_TXN_NO_STATE" ]; then
  date "+${scriptname} transactions made with 'goal method --create' are not equal (C) %Y%m%d_%H%M%S"
  false
fi

date "+${scriptname} OK %Y%m%d_%H%M%S"
