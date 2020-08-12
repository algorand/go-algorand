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

function call_admin {
  curl -q -s -H "Authorization: Bearer ${ADMIN_TOKEN}" "$NET$1"
}

function call {
  curl -q -s -H "Authorization: Bearer ${PUB_TOKEN}" "$NET$1"
}

# $1 - test description.
# $2 - query
# $3 - substring that should be in the response
function call_and_verify {
  local RES
  RES=$(call "$2")
  if [[ "$RES" != *"$3"* ]]; then
    echo "Failed test - $2: $1"
    exit 1
  fi
}


function test_applications_endpoint {
  # Create an application
  printf '#pragma version 2\nint 1' > "${TEMPDIR}/simple.teal"
  APPID=$(${gcmd} app create --creator "${ACCOUNT}" --approval-prog "${TEMPDIR}/simple.teal" --clear-prog "${TEMPDIR}/simple.teal" --global-byteslices 0 --global-ints 2 --local-byteslices 0 --local-ints 0 | grep Created | awk '{ print $6 }')

  # Good request, non-existant app id
  call_and_verify "Should not find app." "/v2/applications/987654321" 'application does not exist'
  # Good request
  call_and_verify "Should contain app data." "/v2/applications/$APPID" '"global-state-schema":{"num-byte-slice":0,"num-uint":2}'
  # Good request, pretty response
  call_and_verify "Should contain app data." "/v2/applications/$APPID?pretty" '
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
  call_and_verify "Parameter parsing error." /v2/applications/-2 "Invalid format for parameter application-id"
  call_and_verify "Parameter parsing error." /v2/applications/not-a-number "Invalid format for parameter application-id"

  # Good request, but invalid query parameters
  call_and_verify "Invalid parameter" "/v2/applications/$APPID?this-should-fail=200" 'Unknown parameter detected: this-should-fail'
}

test_applications_endpoint
