#!/usr/bin/env bash
# TIMEOUT=600

my_dir="$(dirname "$0")"
#"$my_dir/rest.sh" "$@"
source "$my_dir/../rest.sh" "$@"

date "+$0 start %Y%m%d_%H%M%S"

NUM_TRANSACTIONS=0

# Create a transaction with no siblings
while [[ "${NUM_TRANSACTIONS}" != "1" ]]; do
  SEND_OUTPUT=$(${gcmd} clerk send -a 0 -f "${ACCOUNT}" -t "${ACCOUNT}")
  TXID=$(echo "$SEND_OUTPUT" | head -n 1 | sed 's/.*transaction ID: \([^.]*\).*/\1/')
  ROUND=$(echo "$SEND_OUTPUT" | tail -n 1 | sed 's/.*committed in round \([[:digit:]]*\).*/\1/')

  # check if the transaction was all alone in the round
  call_and_verify "Checking block" "/v2/blocks/${ROUND}" 200 'txns'
  #TODO: The check with jq can be re-enabled after fixing JSONStrictHandle.
  #NUM_TRANSACTIONS=$(cat "${TEMPDIR}/curl_out.txt" | jq '.block.txns | length')
  NUM_TRANSACTIONS=$(cat "${TEMPDIR}/curl_out.txt" | grep type | wc -l | tr -d ' ')
done

call_and_verify "The proof should not be null." "/v2/blocks/${ROUND}/transactions/${TXID}/proof" 200 '"proof":""'
