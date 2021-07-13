#!/usr/bin/env bash
# TIMEOUT=300

my_dir="$(dirname "$0")"
#"$my_dir/rest.sh" "$@"
source "$my_dir/rest.sh" "$@"

date "+$0 start %Y%m%d_%H%M%S"

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
