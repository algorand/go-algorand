#!/bin/bash

date '+goal-account-app-test start %Y%m%d_%H%M%S'

set -e
set -x
set -o pipefail
export SHELLOPTS

WALLET=$1

gcmd="goal -w ${WALLET}"

ACCOUNTA=$(${gcmd} account list|awk '{ print $3 }')
ACCOUNTB=$(${gcmd} account new|awk '{ print $6 }')

APP_INDEX_PATTERN='Created app with app index [[:digit:]]+'

# fund account B enough for opt-ins
${gcmd} clerk send -a 10000000 -f ${ACCOUNTA} -t ${ACCOUNTB}

# approval program mostly approves; also sets a local int if called with any args
printf '#pragma version 5\ntxn NumAppArgs; bz done; txn Sender; byte "X"; int 7; app_local_put; done: int 1' > "${TEMPDIR}/approval.teal"
printf '#pragma version 5\nint 1' > "${TEMPDIR}/clear.teal"

# create all apps from account A, with varying global int needs so the schema is visible
RES=$(${gcmd} app create --creator ${ACCOUNTA} --approval-prog "${TEMPDIR}/approval.teal" --clear-prog "${TEMPDIR}/clear.teal" --global-ints 1 --global-byteslices 0 --local-ints 1 --local-byteslices 0)
APP_A_ID=$(echo ${RES} | grep -Eo "${APP_INDEX_PATTERN}" | grep -Eo '[[:digit:]]+')

RES=$(${gcmd} app create --creator ${ACCOUNTA} --approval-prog "${TEMPDIR}/approval.teal" --clear-prog "${TEMPDIR}/clear.teal" --global-ints 1 --global-byteslices 0 --local-ints 2 --local-byteslices 0)
APP_B_ID=$(echo ${RES} | grep -Eo "${APP_INDEX_PATTERN}" | grep -Eo '[[:digit:]]+')

RES=$(${gcmd} app create --creator ${ACCOUNTA} --approval-prog "${TEMPDIR}/approval.teal" --clear-prog "${TEMPDIR}/clear.teal" --global-ints 1 --global-byteslices 0 --local-ints 3 --local-byteslices 0)
APP_C_ID=$(echo ${RES} | grep -Eo "${APP_INDEX_PATTERN}" | grep -Eo '[[:digit:]]+')

RES=$(${gcmd} app create --creator ${ACCOUNTA} --approval-prog "${TEMPDIR}/approval.teal" --clear-prog "${TEMPDIR}/clear.teal" --global-ints 1 --global-byteslices 0 --local-ints 4 --local-byteslices 0)
APP_D_ID=$(echo ${RES} | grep -Eo "${APP_INDEX_PATTERN}" | grep -Eo '[[:digit:]]+')

# query account A's apps with --include-params; although A is not
# opted-in, A is the creator so params are returned, (1)
RES=$(${gcmd} account applicationdetails -a ${ACCOUNTA} -l 2 --include-params)
if [[ ${RES} != *"Account: ${ACCOUNTA}"* ]]; then
    date '+goal-account-app-test applicationdetails (1) should be for correct account %Y%m%d_%H%M%S'
    false
fi
if [[ ${RES} != *"Application ID: ${APP_A_ID}"* ]]; then
    date '+goal-account-app-test applicationdetails (1) should contain app A %Y%m%d_%H%M%S'
    false
fi
if [[ ${RES} != *"Application ID: ${APP_B_ID}"* ]]; then
    date '+goal-account-app-test applicationdetails (1) should contain app B %Y%m%d_%H%M%S'
    false
fi
if [[ ${RES} != *"Creator: ${ACCOUNTA}"* ]]; then
    date '+goal-account-app-test applicationdetails (1) should show creator for app A %Y%m%d_%H%M%S'
    false
fi
# C and D should not appear because of limit
if [[ ${RES} == *"Application ID: ${APP_C_ID}"* ]]; then
    date '+goal-account-app-test applicationdetails (1) should not contain app C %Y%m%d_%H%M%S'
    false
fi
if [[ ${RES} == *"Application ID: ${APP_D_ID}"* ]]; then
    date '+goal-account-app-test applicationdetails (1) should not contain app D %Y%m%d_%H%M%S'
    false
fi
if [[ ${RES} != *"NextToken"* ]]; then
    date '+goal-account-app-test applicationdetails (1) should have a NextToken %Y%m%d_%H%M%S'
    false
fi

# opt account B into all apps, set locals on some so we can check them
${gcmd} app optin --app-id ${APP_A_ID} --from ${ACCOUNTB} --app-arg=int:1
${gcmd} app optin --app-id ${APP_B_ID} --from ${ACCOUNTB}
${gcmd} app optin --app-id ${APP_C_ID} --from ${ACCOUNTB} --app-arg=int:1
${gcmd} app optin --app-id ${APP_D_ID} --from ${ACCOUNTB}

# displays opted-in apps
${gcmd} account info -a ${ACCOUNTB}

# query account B's apps without pagination (default limit holds all apps), (2)
RES=$(${gcmd} account applicationdetails -a ${ACCOUNTB} --include-params)
if [[ ${RES} != *"Account: ${ACCOUNTB}"* ]]; then
    date '+goal-account-app-test applicationdetails (2) should be for correct account %Y%m%d_%H%M%S'
    false
fi
if [[ ${RES} != *"Application ID: ${APP_A_ID}"* ]]; then
    date '+goal-account-app-test applicationdetails (2) should contain app A %Y%m%d_%H%M%S'
    false
fi
if [[ ${RES} != *"Local State: 1/1 uints"* ]]; then
    date '+goal-account-app-test applicationdetails (2) app A should have 1/1 locals set %Y%m%d_%H%M%S'
    false
fi
if [[ ${RES} != *"Application ID: ${APP_B_ID}"* ]]; then
    date '+goal-account-app-test applicationdetails (2) should contain app B %Y%m%d_%H%M%S'
    false
fi
if [[ ${RES} != *"Local State: 0/2 uints"* ]]; then
    date '+goal-account-app-test applicationdetails (2) app B should have 0/2 locals set %Y%m%d_%H%M%S'
    false
fi
if [[ ${RES} != *"Application ID: ${APP_C_ID}"* ]]; then
    date '+goal-account-app-test applicationdetails (2) should contain app C %Y%m%d_%H%M%S'
    false
fi
if [[ ${RES} != *"Local State: 1/3 uints"* ]]; then
    date '+goal-account-app-test applicationdetails (2) app C should have 1/3 locals set %Y%m%d_%H%M%S'
    false
fi
if [[ ${RES} != *"Application ID: ${APP_D_ID}"* ]]; then
    date '+goal-account-app-test applicationdetails (2) should contain app D %Y%m%d_%H%M%S'
    false
fi
if [[ ${RES} != *"Local State: 0/4 uints"* ]]; then
    date '+goal-account-app-test applicationdetails (2) app D should have 0/4 locals set %Y%m%d_%H%M%S'
    false
fi
# All four applications should have ACCOUNTA as creator listed
if [[ $(grep -c "Creator: ${ACCOUNTA}" <<<"${RES}") -ne 4 ]]; then
    date '+goal-account-app-test applicationdetails (2) should have 4 Creator lines %Y%m%d_%H%M%S'
    false
fi
# All four applications should have globals listed
if [[ $(grep -c 'Global State:' <<<"${RES}") -ne 4 ]]; then
    date '+goal-account-app-test applicationdetails (2) should have 4 Global State lines %Y%m%d_%H%M%S'
    false
fi

# Do not include params
RES=$(${gcmd} account applicationdetails -a ${ACCOUNTB})
# without --include-params, no creator info should appear
if [[ ${RES} == *"Creator:"* ]]; then
    date '+goal-account-app-test applicationdetails (2) should not show creator without --include-params %Y%m%d_%H%M%S'
    false
fi
if [[ ${RES} == *"Global State:"* ]]; then
    date '+goal-account-app-test applicationdetails (2) should not show globals without --include-params %Y%m%d_%H%M%S'
    false
fi

# query account B's apps with pagination, limit 2, next set to app B, (3)
RES=$(${gcmd} account applicationdetails -a ${ACCOUNTB} -l 2 -n ${APP_B_ID})
if [[ ${RES} != *"Account: ${ACCOUNTB}"* ]]; then
    date '+goal-account-app-test applicationdetails (3) should be for correct account %Y%m%d_%H%M%S'
    false
fi
if [[ ${RES} == *"Application ID: ${APP_A_ID}"* ]]; then
    date '+goal-account-app-test applicationdetails (3) should not contain app A %Y%m%d_%H%M%S'
    false
fi
if [[ ${RES} == *"Application ID: ${APP_B_ID}"* ]]; then
    date '+goal-account-app-test applicationdetails (3) should not contain app B %Y%m%d_%H%M%S'
    false
fi
if [[ ${RES} != *"Application ID: ${APP_C_ID}"* ]]; then
    date '+goal-account-app-test applicationdetails (3) should contain app C %Y%m%d_%H%M%S'
    false
fi
if [[ ${RES} != *"Application ID: ${APP_D_ID}"* ]]; then
    date '+goal-account-app-test applicationdetails (3) should contain app D %Y%m%d_%H%M%S'
    false
fi
if [[ ${RES} == *"NextToken"* ]]; then
    date '+goal-account-app-test applicationdetails (3) should not have a NextToken %Y%m%d_%H%M%S'
    false
fi

# delete app B
${gcmd} app delete --app-id ${APP_B_ID} --from ${ACCOUNTA}

# query account B's apps with --include-params after deletion, (4)
RES=$(${gcmd} account applicationdetails -a ${ACCOUNTB} --include-params)
if [[ ${RES} != *"Account: ${ACCOUNTB}"* ]]; then
    date '+goal-account-app-test applicationdetails (4) should be for correct account %Y%m%d_%H%M%S'
    false
fi
if [[ ${RES} != *"Application ID: ${APP_A_ID}"* ]]; then
    date '+goal-account-app-test applicationdetails (4) should contain app A %Y%m%d_%H%M%S'
    false
fi
# app B is deleted but account B is still opted in, so it still appears
if [[ ${RES} != *"Application ID: ${APP_B_ID}"* ]]; then
    date '+goal-account-app-test applicationdetails (4) should still contain app B after deletion %Y%m%d_%H%M%S'
    false
fi
if [[ ${RES} != *"Application ID: ${APP_C_ID}"* ]]; then
    date '+goal-account-app-test applicationdetails (4) should contain app C %Y%m%d_%H%M%S'
    false
fi
if [[ ${RES} != *"Application ID: ${APP_D_ID}"* ]]; then
    date '+goal-account-app-test applicationdetails (4) should contain app D %Y%m%d_%H%M%S'
    false
fi

date '+goal-account-app-test OK %Y%m%d_%H%M%S'
