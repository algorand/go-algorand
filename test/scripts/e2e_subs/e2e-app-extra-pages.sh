#!/bin/bash

date '+app-extra-pages-test start %Y%m%d_%H%M%S'

set -e
set -x
set -o pipefail
export SHELLOPTS

WALLET=$1

gcmd="goal -w ${WALLET}"

ACCOUNT=$(${gcmd} account list|awk '{ print $3 }')

function generate_teal() {
    FILE=$1
    VERSION=$2
    SIZE=$3
    COST=$4
    PREFIX=$5

    printf '#pragma version %d\n' $VERSION > "${FILE}"
    printf "${PREFIX}\n" >> "${FILE}"

    # i = 5; i <= SIZE - 1; i += 2
    for i in $(seq 5 2 $(expr $SIZE - 1)); do
        printf "int 1\npop\n" >> "${FILE}"
    done

    if [ "$COST" -gt "$(expr $SIZE '*' 2)" ]; then
        # i = SIZE * 2; i <= COST - 1; i += 130
        for i in $(seq $(expr $SIZE '*' 2) 130 $(expr $COST - 1)); do
            printf "keccak256\n" >> "${FILE}"
        done
        printf "pop\n" >> "${FILE}"
    fi

    printf "int 1\n" >> "${FILE}"
}

BIG_TEAL_FILE="$TEMPDIR/big-app.teal"
BIG_TEAL_V4_FILE="$TEMPDIR/big-app-v4.teal"
SMALL_TEAL_FILE="$TEMPDIR/sm-app.teal"
APPR_PROG="$TEMPDIR/appr-prog.teal"
BIG_APPR_PROG="$TEMPDIR/big-appr-prog.teal"

generate_teal "$BIG_TEAL_FILE" 3 4090 1 "int 0\nbalance\npop\n"
generate_teal "$BIG_TEAL_V4_FILE" 4 4090 1 "int 0\nbalance\npop\n"
generate_teal "$SMALL_TEAL_FILE" 3 10 1 "int 0\nbalance\npop\n"
generate_teal "$APPR_PROG" 4 3072 1 "int 0\nbalance\npop\n"
generate_teal "$BIG_APPR_PROG" 4 4098 1 "int 0\nbalance\npop\n"

# App create fails. Approval program too long
RES=$(${gcmd} app create --creator ${ACCOUNT} --approval-prog "${BIG_TEAL_FILE}" --clear-prog "${BIG_TEAL_FILE}" --global-byteslices 1 --global-ints 0 --local-byteslices 0 --local-ints 0 2>&1 || true)
EXPERROR="approval program too long. max len 2048 bytes"
if [[ $RES != *"${EXPERROR}"* ]]; then
    date '+app-extra-pages-test FAIL the application creation should fail %Y%m%d_%H%M%S'
    false
fi

# App create fails. Clear state program too long
RES=$(${gcmd} app create --creator ${ACCOUNT} --approval-prog "${SMALL_TEAL_FILE}" --clear-prog "${BIG_TEAL_FILE}" --global-byteslices 1 --global-ints 0 --local-byteslices 0 --local-ints 0 2>&1 || true)
EXPERROR="clear state program too long. max len 2048 bytes"
if [[ $RES != *"${EXPERROR}"* ]]; then
    date '+app-extra-pages-test FAIL the application creation should fail %Y%m%d_%H%M%S'
    false
fi

# App create with extra pages, v3 teal
RES=$(${gcmd} app create --creator ${ACCOUNT} --approval-prog "${BIG_TEAL_FILE}" --clear-prog "${BIG_TEAL_FILE}" --extra-pages 3 --global-byteslices 1 --global-ints 0 --local-byteslices 0 --local-ints 0 2>&1 || true)
EXPERROR="pc=705 static cost budget of 700 exceeded"
if [[ $RES != *"${EXPERROR}"* ]]; then
    date '+app-extra-pages-test FAIL the application creation should fail %Y%m%d_%H%M%S'
    false
fi

# App create with extra pages, v4 teal
RES=$(${gcmd} app create --creator ${ACCOUNT} --approval-prog "${BIG_TEAL_V4_FILE}" --clear-prog "${BIG_TEAL_V4_FILE}" --extra-pages 3 --global-byteslices 1 --global-ints 0 --local-byteslices 0 --local-ints 0 2>&1 || true)
EXPERROR="pc=704 dynamic cost budget exceeded, executing intc_0: remaining budget is 700 but program cost was 701"
if [[ $RES != *"${EXPERROR}"* ]]; then
    date '+app-extra-pages-test FAIL the application creation should fail %Y%m%d_%H%M%S'
    false
fi

# App create with extra pages, succeeded
RES=$(${gcmd} app create --creator ${ACCOUNT} --approval-prog "${SMALL_TEAL_FILE}" --clear-prog "${SMALL_TEAL_FILE}" --extra-pages 1 --global-byteslices 1 --global-ints 0 --local-byteslices 0 --local-ints 0 2>&1 || true)
EXP="Created app"
APPID=$(echo $RES | awk '{print $NF}')
if [[ $RES != *"${EXP}"* ]]; then
    date '+app-extra-pages-test FAIL the application creation should pass %Y%m%d_%H%M%S'
    false
fi

RES=$(${gcmd} app info --app-id ${APPID}  2>&1 || true)
PROGHASH="Approval hash:         7356635AKR4FJOOKXXBWNN6HDJ5U3O2YWAOSK6NZBPMOGIQSWCL2N74VT4"
EXTRAPAGES="Extra program pages:   1"
if [[ $RES != *"${PROGHASH}"* ]]; then
    date '+app-extra-pages-test FAIL the application approval program hash is incorrect %Y%m%d_%H%M%S'
    false
fi
if [[ $RES != *"${EXTRAPAGES}"* ]]; then
    date '+app-extra-pages-test FAIL the application extra pages value is incorrect %Y%m%d_%H%M%S'
    false
fi

RES=$(${gcmd} app update --app-id ${APPID} --approval-prog "${APPR_PROG}" --clear-prog "${SMALL_TEAL_FILE}" --from ${ACCOUNT} 2>&1 || true)
EXP="Attempting to update app"
if [[ $RES != *"${EXP}"* ]]; then
    date '+app-extra-pages-test FAIL the application update should succeed %Y%m%d_%H%M%S'
    false
fi

RES=$(${gcmd} app info --app-id ${APPID}  2>&1 || true)
if [[ $RES == *"${PROGHASH}"* ]]; then
    date '+app-extra-pages-test FAIL the application approval program should have been updated %Y%m%d_%H%M%S'
    false
fi
if [[ $RES != *"${EXTRAPAGES}"* ]]; then
    date '+app-extra-pages-test FAIL the application extra pages value is incorrect after update %Y%m%d_%H%M%S'
    false
fi
