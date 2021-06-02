#!/usr/bin/env bash
# TIMEOUT=300

my_dir="$(dirname "$0")"
#"$my_dir/rest.sh" "$@"
source "$my_dir/rest.sh" "$@"

date "+$0 start %Y%m%d_%H%M%S"

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

