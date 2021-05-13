#!/usr/bin/env bash
# TIMEOUT=300

date '+rest.sh start %Y%m%d_%H%M%S'

set -ex
set -o pipefail
export SHELLOPTS

WALLET=$1
gcmd="goal -w ${WALLET}"
ACCOUNT=$(${gcmd} account list|awk '{ print $3 }')

# REST Parameters
PUB_TOKEN=$(cat "$ALGORAND_DATA"/algod.token)
ADMIN_TOKEN=$(cat "$ALGORAND_DATA"/algod.admin.token)
NET=$(cat "$ALGORAND_DATA"/algod.net)

PRIMARY_NET=$(cat "$ALGORAND_DATA2"/algod.net)
PRIMARY_ADMIN_TOKEN=$(cat "$ALGORAND_DATA2"/algod.admin.token)


function base_call {
  curl -o "$3" -w "%{http_code}" -q -s -H "Authorization: Bearer $1" "$NET$2"
}


function call_admin {
  base_call "$ADMIN_TOKEN" "$1" "$2"
}


function call {
  base_call "$PUB_TOKEN" "$1" "$2"
}


function fail_and_exit {
  printf "\n\nFailed test - $1 ($2): $3\n\n"
  exit 1
}


# $1 - test description.
# $2 - query
# $3 - expected status code
# $4 - substring that should be in the response
function call_and_verify {
  local CODE

  set +e
  CODE=$(call "$2" "${TEMPDIR}/curl_out.txt")
  if [[ $? != 0 ]]; then
    fail_and_exit "$1" "$2" "curl had a non-zero exit code."
  fi
  set -e

  RES=$(cat "${TEMPDIR}/curl_out.txt")
  if [[ "$CODE" != "$3" ]]; then
    fail_and_exit "$1" "$2" "unexpected HTTP status code expected $3 (actual $CODE)"
  fi
  if [[ "$RES" != *"$4"* ]]; then
    fail_and_exit "$1" "$2" "unexpected response. should contain '$4', actual: $RES"
  fi
}


function test_applications_endpoint {
  # Create an application
  printf '#pragma version 2\nint 1' > "${TEMPDIR}/simple.teal"
  APPID=$(${gcmd} app create --creator "${ACCOUNT}" --approval-prog "${TEMPDIR}/simple.teal" --clear-prog "${TEMPDIR}/simple.teal" --global-byteslices 0 --global-ints 2 --local-byteslices 0 --local-ints 0 | grep Created | awk '{ print $6 }')

  # Good request, non-existant app id
  call_and_verify "Should not find app." "/v2/applications/987654321" 404 'application does not exist'
  # Good request
  call_and_verify "Should contain app data." "/v2/applications/$APPID" 200 '"global-state-schema":{"num-byte-slice":0,"num-uint":2}'
  # Good request, pretty response
  call_and_verify "Should contain app data." "/v2/applications/$APPID?pretty" 200 '
    "global-state-schema": {
      "num-byte-slice": 0,
      "num-uint": 2
    },
    "local-state-schema": {
      "num-byte-slice": 0,
      "num-uint": 0
    }
'
  # Some invalid path parameters
  call_and_verify "App parameter parsing error 1." "/v2/applications/-2" 400 "Invalid format for parameter application-id"
  call_and_verify "App parameter parsing error 2." "/v2/applications/not-a-number" 400 "Invalid format for parameter application-id"

  # Good request, but invalid query parameters
  call_and_verify "App invalid parameter" "/v2/applications/$APPID?this-should-fail=200" 400 'Unknown parameter detected: this-should-fail'
}


function test_assets_endpoint {
  local ASSET_ID
  ASSET_ID=$(${gcmd} asset create --creator "${ACCOUNT}" --total 10000 --decimals 19 --name "spanish coin" --unitname "doubloon" | grep "Created asset with asset index" | rev | cut -d ' ' -f 1 | rev)

  # Good request, non-existant asset id
  call_and_verify "Should not find asset." "/v2/assets/987654321" 404 'asset does not exist'
  # Good request
  call_and_verify "Should contain asset data." "/v2/assets/$ASSET_ID" 200 '","decimals":19,"default-frozen":false,"freeze":"'
  # Good request, pretty response
  call_and_verify "Should contain asset data." "/v2/assets/$ASSET_ID?pretty" 200 '
    "decimals": 19,
    "default-frozen": false,
    "freeze": "'
  # Some invalid path parameters
  call_and_verify "Asset parameter parsing error 1." "/v2/assets/-2" 400 "Invalid format for parameter asset-id"
  call_and_verify "Asset parameter parsing error 2." "/v2/assets/not-a-number" 400 "Invalid format for parameter asset-id"

  # Good request, but invalid query parameters
  call_and_verify "Asset invalid parameter" "/v2/assets/$ASSET_ID?this-should-fail=200" 400 'parameter detected: this-should-fail'
}

function pprof_test {
  # URL Auth - valid
  CODE=$(curl -o "${TEMPDIR}/curl_out.txt" -w "%{http_code}" -q -s "$PRIMARY_NET/urlAuth/$PRIMARY_ADMIN_TOKEN/debug/pprof/block")
  if [[ "$CODE" != "200" ]]; then
    fail_and_exit "Call pprof with valid token" "/urlAuth/:token/debug/pprof" "Invalid exit code expected 200 (actual $CODE)"
  fi

  # URL Auth - invalid
  CODE=$(curl -o "${TEMPDIR}/curl_out.txt" -w "%{http_code}" -q -s "$PRIMARY_NET/urlAuth/invalid_token/debug/pprof/block")
  if [[ "$CODE" != "401" ]]; then
    fail_and_exit "Call pprof with invalid token" "/urlAuth/invalid_token/debug/pprof" "Invalid exit code expected 401 (actual $CODE)"
  fi

  # Header Auth - valid
  CODE=$(curl -o "${TEMPDIR}/curl_out.txt" -w "%{http_code}" -q -s "$PRIMARY_NET/debug/pprof/block" -H "Authorization: Bearer $PRIMARY_ADMIN_TOKEN")
  if [[ "$CODE" != "200" ]]; then
    fail_and_exit "Call pprof with valid token" "/debug/pprof" "Invalid exit code expected 200 (actual $CODE)"
  fi

  # Header Auth - invalid
  CODE=$(curl -o "${TEMPDIR}/curl_out.txt" -w "%{http_code}" -q -s "$PRIMARY_NET/debug/pprof/block" -H "Authorization: Bearer invalid_token")
  if [[ "$CODE" != "401" ]]; then
    fail_and_exit "Call pprof with invalid token" "/debug/pprof" "Invalid exit code expected 401 (actual $CODE)"
  fi
}

function test_genesis_endpoint {
  call_and_verify "There should be a genesis endpoint." "/genesis" 200 '
  "id": "v1",
  "network": "tbd",
  "proto": "future",
  "rwd": "7777777777777777777777777777777777777777777777777774MSJUVU"
}'
}

function test_proof {
  NUM_TRANSACTIONS=0

  # Create a transaction with no siblings
  while [[ "${NUM_TRANSACTIONS}" != "1" ]]; do
    SEND_OUTPUT=$(${gcmd} clerk send -a 0 -f "${ACCOUNT}" -t "${ACCOUNT}")
    TXID=$(echo "$SEND_OUTPUT" | head -n 1 | sed 's/.*transaction ID: \([^.]*\).*/\1/')
    ROUND=$(echo "$SEND_OUTPUT" | tail -n 1 | sed 's/.*committed in round \([[:digit:]]*\).*/\1/')

    # check if the transaction was all alone in the round
    call_and_verify "Checking block" "/v2/blocks/${ROUND}" 200 'txns'
    NUM_TRANSACTIONS=$(cat "${TEMPDIR}/curl_out.txt" | jq '.block.txns | length')
  done

  call_and_verify "The proof should not be null." "/v2/blocks/${ROUND}/transactions/${TXID}/proof" 200 '"proof":""'
}

# Run the tests.
test_applications_endpoint
test_assets_endpoint
pprof_test
test_genesis_endpoint
test_proof
