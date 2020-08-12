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

function base_call {
  curl -q -s -H "Authorization: Bearer $1" "$NET$2"
}

function call_admin {
  base_call "$ADMIN_TOKEN" "$1"
}

function call {
  base_call "$PUB_TOKEN" "$1"
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
  call_and_verify "App parameter parsing error 1." "/v2/applications/-2" "Invalid format for parameter application-id"
  call_and_verify "App parameter parsing error 2." "/v2/applications/not-a-number" "Invalid format for parameter application-id"

  # Good request, but invalid query parameters
  call_and_verify "App invalid parameter" "/v2/applications/$APPID?this-should-fail=200" 'Unknown parameter detected: this-should-fail'
}

function test_assets_endpoint {
  local DIR
  local ASSET_ID

  # Directory of helper TEAL programs
  DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )/tealprogs"
  RES=$(${gcmd} asset create --creator "${ACCOUNT}" --total 10000 --decimals 19 --name "spanish coin" --unitname "doubloon")
  echo $RES
  ASSET_ID=$(echo $RES | grep "Created asset with asset index" | rev | cut -d ' ' -f 1 | rev)
  echo "ASSET_ID: $ASSET_ID"

  # Good request, non-existant asset id
  call_and_verify "Should not find asset." "/v2/assets/987654321" 'asset does not exist'
  # Good request
  call_and_verify "Should contain asset data." "/v2/assets/$ASSET_ID" '","decimals":19,"default-frozen":false,"freeze":"'
  # Good request, pretty response
  call_and_verify "Should contain asset data." "/v2/assets/$ASSET_ID?pretty" '
    "decimals": 19,
    "default-frozen": false,
    "freeze": "'
  # Some invalid path parameters
  call_and_verify "Asset parameter parsing error 1." "/v2/assets/-2" "Invalid format for parameter asset-id"
  call_and_verify "Asset parameter parsing error 2." "/v2/assets/not-a-number" "Invalid format for parameter asset-id"

  # Good request, but invalid query parameters
  call_and_verify "Asset invalid parameter" "/v2/assets/$ASSET_ID?this-should-fail=200" 'parameter detected: this-should-fail'
}

pids=()
# Run all the tests in parallel
test_applications_endpoint & pids+=($!)
test_assets_endpoint & pids+=($!)

# Wait for them to complete and propogate the error code
EXIT=0
for pid in ${pids[*]}; do
  wait $pid
  if [ $? -ne 0 ]; then
    EXIT=1
  fi
done
exit $EXIT
