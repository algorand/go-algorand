#!/usr/bin/env bash
# TIMEOUT=50

# Helpers for REST API tests.
# Use the following boilerplate code at the top of new REST tests:

#    #!/usr/bin/env bash
#    # TIMEOUT=300
#    
#    my_dir="$(dirname "$0")"
#    #"$my_dir/rest.sh" "$@"
#    source "$my_dir/rest.sh" "$@"
#    
#    date "+$0 start %Y%m%d_%H%M%S"

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
# $4... - substring that should be in the response
function call_and_verify {
  local DESCRIPTION="$1"
  shift
  local QUERY="$1"
  shift
  local EXPECTED_CODE="$1"
  shift

  echo "MATCHING $@"
  curl_test "$DESCRIPTION" "$QUERY" "$EXPECTED_CODE" true "$@"
}

# CURL Test - query and veryify results
# $1 - test description.
# $2 - query
# $3 - expected status code
# $4 - match result
# $5... - substring(s) that should be in the response
function curl_test {
  local DESCRIPTION="$1"
  shift
  local QUERY="$1"
  shift
  local EXPECTED_CODE="$1"
  shift
  local MATCH_RESULT="$1"
  shift
  local SUBSTRING

  local START=$SECONDS

  set +e
  local CODE=$(call "$QUERY" "${TEMPDIR}/curl_out.txt")
  if [[ $? != 0 ]]; then
    cat $CURL_TEMPFILE
    fail_and_exit "$DESCRIPTION" "$QUERY" "curl had a non-zero exit code."
  fi
  set -e

  RES=$(cat "${TEMPDIR}/curl_out.txt")
  if [[ "$CODE" != "$EXPECTED_CODE" ]]; then
    fail_and_exit "$DESCRIPTION" "$QUERY" "unexpected HTTP status code expected $EXPECTED_CODE (actual $CODE): $RES"
  fi

  #local ELAPSED=$(($SECONDS - $START))
  #if [[ $ELAPSED -gt $MAX_TIME ]]; then
  #  fail_and_exit "$DESCRIPTION" "$QUERY" "query duration too long, $ELAPSED > $MAX_TIME"
  #fi

  # Check result substrings
  for SUBSTRING in "$@"; do
    echo "CHECKING '$SUBSTRING'"
    if [[ $MATCH_RESULT = true ]]; then
      if [[ "$RES" != *"$SUBSTRING"* ]]; then
        fail_and_exit "$DESCRIPTION" "$QUERY" "unexpected response. should contain '$SUBSTRING', actual: $RES"
      fi
    else
      if [[ "$RES" == *"$SUBSTRING"* ]]; then
        fail_and_exit "$DESCRIPTION" "$QUERY" "unexpected response. should NOT contain '$SUBSTRING', actual: $RES"
      fi
    fi
  done
}
