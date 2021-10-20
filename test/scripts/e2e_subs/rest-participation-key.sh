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

call_post_and_verify "Install a basic participation key" "/v2/participation" 200 ${NAME_OF_TEMP_PARTKEY} 'partId'

call_and_verify "Get List of Keys" "/v2/participation" 200 'Address'

# Let's get a key from the previous response manually and request it specifically
SAMPLE_ID=$(curl -q -s -H "Authorization: Bearer $ADMIN_TOKEN" "$NET/v2/participation" | python3 -c 'import json,sys;obj=json.load(sys.stdin);print(obj[0]["ID"])')
NUMBER_OF_IDS=$(curl -q -s -H "Authorization: Bearer $ADMIN_TOKEN" "$NET/v2/participation" | python3 -c 'import json,sys;obj=json.load(sys.stdin);print(len(obj))')

call_and_verify "Get a specific ID" "/v2/participation/${SAMPLE_ID}" 200 "${SAMPLE_ID}"

call_delete_and_verify "Delete the specific ID" "/v2/participation/${SAMPLE_ID}" 200

# Verify that it got called previously and will NOT return an error now even though it isn't there
call_delete_and_verify "Delete the specific ID" "/v2/participation/${SAMPLE_ID}" 200

NEW_NUMBER_OF_IDS=$(curl -q -s -H "Authorization: Bearer $ADMIN_TOKEN" "$NET/v2/participation" | python3 -c 'import json,sys;obj=json.load(sys.stdin);print(len(obj))')

if [[ "$NEW_NUMBER_OF_IDS" -ge "$NUMBER_OF_IDS" ]]; then
  printf "\n\nFailed test.  New number of IDs (%s) is greater than or equal to original IDs (%s)\n\n" "${NEW_NUMBER_OF_IDS}" "${NUMBER_OF_IDS}"
  exit 1
fi


