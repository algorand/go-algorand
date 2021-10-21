#!/usr/bin/env bash
# TIMEOUT=300

my_dir="$(dirname "$0")"
source "$my_dir/rest.sh" "$@"

date "+$0 start %Y%m%d_%H%M%S"

# Use admin token for both get and post
export USE_ADMIN=true

pushd "${TEMPDIR}" || exit

FIRST_ROUND=0
# A really large (but arbitrary) last valid round
LAST_ROUND=1200000

NAME_OF_TEMP_PARTKEY="tmp.${FIRST_ROUND}.${LAST_ROUND}.partkey"

algokey part generate --first ${FIRST_ROUND} --last ${LAST_ROUND} --keyfile ${NAME_OF_TEMP_PARTKEY} --parent ${ACCOUNT}

popd || exit

call_and_verify "Get List of Keys" "/v2/participation" 200 'Address'

# Find out how many keys there are installed so far
NUM_IDS_1=$(echo "$RES" | python3 -c 'import json,sys;o=json.load(sys.stdin);print(len(o))')

call_post_and_verify "Install a basic participation key" "/v2/participation" 200 ${NAME_OF_TEMP_PARTKEY} 'partId'

# Get the returned participation id from the RESULT (aka $RES) variable
INSTALLED_ID=$(echo "$RES" | python3 -c 'import json,sys;o=json.load(sys.stdin);print(o["partId"])')

# Should contain the installed id
call_and_verify "Get List of Keys" "/v2/participation" 200 'Address' "${INSTALLED_ID}"

# Get list of keys
NUM_IDS_2=$(echo "$RES" | python3 -c 'import json,sys;o=json.load(sys.stdin);print(len(o))')

if [[ $((NUM_IDS_1 + 1)) -ne $NUM_IDS_2 ]]; then
  printf "\n\nFailed test.  New number of IDs (%s) is not one more than old ID count(%s)\n\n" "${NUM_IDS_2}" "${NUM_IDS_1}"
  exit 1
fi

call_and_verify "Get a specific ID" "/v2/participation/${INSTALLED_ID}" 200 "${INSTALLED_ID}"

# Should return 200 but not return that error message
call_delete_and_verify "Delete the specific ID" "/v2/participation/${INSTALLED_ID}" 200 false 'participation id not found'

# Verify that it got called previously and will NOT return an error now even though it isn't there.
# But it will contain a message saying that no key was found
call_delete_and_verify "Delete the specific ID" "/v2/participation/${INSTALLED_ID}" 200 true 'participation id not found'

# Get list of keys
NUM_IDS_3=$(echo "$RES" | python3 -c 'import json,sys;o=json.load(sys.stdin);print(len(o))')

if [[ "$NUM_IDS_3" -ne "$NUM_IDS_1" ]]; then
  printf "\n\nFailed test.  New number of IDs (%s) is not equal to original ID count (%s)\n\n" "${NUM_IDS_3}" "${NUM_IDS_1}"
  exit 1
fi


