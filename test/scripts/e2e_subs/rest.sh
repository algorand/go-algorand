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


function base_post_call {
  curl -X POST --data-binary @/${TEMPDIR}/$4 -o "$3" -w "%{http_code}" -q -s -H "Authorization: Bearer $1" "$NET$2"
}


function base_delete_call {
  curl -X DELETE -o "$3" -w "%{http_code}" -q -s -H "Authorization: Bearer $1" "$NET$2"
}

function call_admin {
  base_call "$ADMIN_TOKEN" "$1" "$2"
}

function call_post_admin {
  base_post_call "$ADMIN_TOKEN" "$1" "$2" "$3"
}

function call_delete_admin {
  base_delete_call "$ADMIN_TOKEN" "$1" "$2" "$3"
}

function call {
  base_call "$PUB_TOKEN" "$1" "$2"
}

function call_post {
  base_post_call "$PUB_TOKEN" "$1" "$2"
}

function call_delete {
  base_delete_call "$PUB_TOKEN" "$1" "$2"
}


function fail_and_exit {
  printf "\n\nFailed test - $1 ($2): $3\n\n"
  exit 1
}

# $1 - test description.
# $2 - query
# $3 - expected status code
# $4 - the file to upload
# $5... - substring that should be in the response
function call_post_and_verify {
   local DESCRIPTION="$1"
   shift
   local QUERY="$1"
   shift
   local EXPECTED_CODE="$1"
   shift
   local FILENAME_TO_UPLOAD="$1"
   shift

   echo "MATCHING $@"
   curl_post_test "$DESCRIPTION" "$QUERY" "$EXPECTED_CODE" true "$FILENAME_TO_UPLOAD" "$@"
}


# CURL POST Test - POST query and verify results
# $1 - test description.
# $2 - query
# $3 - expected status code
# $4 - match result
# $5 - the file to upload
# $6... - substring(s) that should be in the response
function curl_post_test {
  local DESCRIPTION="$1"
  shift
  local QUERY="$1"
  shift
  local EXPECTED_CODE="$1"
  shift
  local MATCH_RESULT="$1"
  shift
  local FILENAME_TO_UPLOAD="$1"
  shift


  local SUBSTRING

  local START=$SECONDS

  set +e
  local CODE
  if [[ "$USE_ADMIN" = true ]]; then
    CODE=$(call_post_admin "$QUERY" "${TEMPDIR}/curl_out.txt" "$FILENAME_TO_UPLOAD")
  else
    CODE=$(call_post "$QUERY" "${TEMPDIR}/curl_out.txt" "$FILENAME_TO_UPLOAD")
  fi
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

# $1 - test description.
# $2 - query
# $3 - expected status code
# $4... - substring that should be in the response
function call_delete_and_verify {
  local DESCRIPTION="$1"
  shift
  local QUERY="$1"
  shift
  local EXPECTED_CODE="$1"
  shift

  curl_delete_test "$DESCRIPTION" "$QUERY" "$EXPECTED_CODE"
}

# CURL Test - query and verify results
# $1 - test description.
# $2 - query
# $3 - expected status code
function curl_delete_test {
  local DESCRIPTION="$1"
  shift
  local QUERY="$1"
  shift
  local EXPECTED_CODE="$1"
  shift

  local START=$SECONDS

  set +e

  local CODE
  if [[ "$USE_ADMIN" = true ]]; then
    CODE=$(call_delete_admin "$QUERY" "${TEMPDIR}/curl_out.txt")
  else
    CODE=$(call_delete "$QUERY" "${TEMPDIR}/curl_out.txt" )
  fi

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
}


# CURL Test - query and verify results
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

  local CODE
  if [[ "$USE_ADMIN" = true ]]; then
    CODE=$(call_admin "$QUERY" "${TEMPDIR}/curl_out.txt")
  else
    CODE=$(call "$QUERY" "${TEMPDIR}/curl_out.txt" )
  fi

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

# CURL Test - query and verify results
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

  local CODE
  if [[ "$USE_ADMIN" = true ]]; then
    CODE=$(call_admin "$QUERY" "${TEMPDIR}/curl_out.txt")
  else
    CODE=$(call "$QUERY" "${TEMPDIR}/curl_out.txt" )
  fi

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
