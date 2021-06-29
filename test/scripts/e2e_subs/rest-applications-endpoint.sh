#!/usr/bin/env bash
# TIMEOUT=300

my_dir="$(dirname "$0")"
#"$my_dir/rest.sh" "$@"
source "$my_dir/rest.sh" "$@"

date "+$0 start %Y%m%d_%H%M%S"

# Create an application
printf '#pragma version 2\nint 1' > "${TEMPDIR}/simple.teal"
APPID=$(${gcmd} app create --creator "${ACCOUNT}" --approval-prog "${TEMPDIR}/simple.teal" --clear-prog "${TEMPDIR}/simple.teal" --global-byteslices 0 --global-ints 2 --local-byteslices 0 --local-ints 0 | grep Created | awk '{ print $6 }')

# Good request, non-existent app id
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

