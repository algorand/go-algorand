#!/usr/bin/env bash
# TIMEOUT=300

my_dir="$(dirname "$0")"
source "$my_dir/rest.sh" "$@"

date "+$0 start %Y%m%d_%H%M%S"

# Use admin token for both get and post
export USE_ADMIN=true

pushd "${TEMPDIR}" || exit 1

FIRST_ROUND=0
# A really large (but arbitrary) last valid round
LAST_ROUND=120

NAME_OF_TEMP_PARTKEY="tmp.${FIRST_ROUND}.${LAST_ROUND}.partkey"

algokey part generate --first ${FIRST_ROUND} --last ${LAST_ROUND} --keyfile ${NAME_OF_TEMP_PARTKEY} --parent ${ACCOUNT}

popd || exit 1

call_and_verify "Get List of Keys" "/v2/participation" 200 'address' 'effective-first-valid'

RES=""
call_post_and_verify "Install a basic participation key" "/v2/participation" 200 ${NAME_OF_TEMP_PARTKEY} 'partId'

# Get the returned participation id from the RESULT (aka $RES) variable
INSTALLED_ID=$(echo "$RES" | python3 -c 'import json,sys;o=json.load(sys.stdin);print(o["partId"])')

# Should contain the installed id
call_and_verify "Get List of Keys" "/v2/participation" 200 'address' "${INSTALLED_ID}" 'address' 'effective-first-valid'

call_and_verify "Get a specific ID" "/v2/participation/${INSTALLED_ID}" 200 "${INSTALLED_ID}"

# Should return 200 but not return that error message
call_delete_and_verify "Delete the specific ID" "/v2/participation/${INSTALLED_ID}" 200 false 'participation id not found'

# Verify that it got called previously and now returns an error message saying that no key was found
call_delete_and_verify "Delete the specific ID" "/v2/participation/${INSTALLED_ID}" 404 true 'participation id not found'
