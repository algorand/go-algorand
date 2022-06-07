#!/usr/bin/env bash
# TIMEOUT=300

# errors are handled manually, so no -e
set -x

date "+$0 start %Y%m%d_%H%M%S"

# Registered  Account      ParticipationID   Last Used  First round  Last round
# yes         LFMT...RHJQ  4UPT6AQC...               4            0     3000000
OUTPUT=$(goal account listpartkeys)
# In case there are multiple keys, make sure we are checking the correct one.
OUTPUT=$(echo "$OUTPUT"|grep "yes.*3000"|tr -s ' ')
if [[ "$OUTPUT"                          != yes*    ]]; then echo "Registered should be 'yes' but wasn't."; exit 1; fi
if [[ $(echo "$OUTPUT" | cut -d' ' -f 4) == 0       ]]; then echo "Last Used shouldn't be 0 but was.";      exit 1; fi
if [[ $(echo "$OUTPUT" | cut -d' ' -f 5) != 0       ]]; then echo "First round should be 0 but wasn't.";    exit 1; fi
if [[ $(echo "$OUTPUT" | cut -d' ' -f 6) != 3000 ]];    then echo "Last round should be 3000 but wasn't.";  exit 1; fi

#Dumping participation key info from /tmp/tmpwtomya9x/net/Node...
#
#Participation ID:          4UPT6AQCFZU5ZDN3WKVPCFYOH2SFJ7SPHK7XPWI2CIDYKK7K3WMQ
#Parent address:            LFMTCXCY6WGSFSGLSNTFH532KVERJVNRD7W5H7GIQ4MPGM7SSVYMQYRHJQ
#Last vote round:           3
#Last block proposal round: 4
#Effective first round:     0
#Effective last round:      3000
#First round:               0
#Last round:                3000
#Key dilution:              10000
#Selection key:             esIsBJB86P+sLeqO3gVoLBGfpuwYlWN4lNzz2AYslTo=
#Voting key:                W1OcXLZsaATyOd5FbhRgXHmcywvn++xEVUAQ0NejmW4=
OUTPUT=$(goal account partkeyinfo)
if ! echo "$OUTPUT" | grep -q 'First round:[[:space:]]* 0';                  then echo "First round should have been 0.";             exit 1; fi
if ! echo "$OUTPUT" | grep -q 'Last round:[[:space:]]* 3000';                then echo "Last round should have been 3000.";           exit 1; fi
if ! echo "$OUTPUT" | grep -q 'Effective last round:[[:space:]]* 3000';      then echo "Effective last round should have been 3000."; exit 1; fi
# 100 or 10000 due to arm64 bug
if ! echo "$OUTPUT" | grep -q 'Key dilution:[[:space:]]* 100\(00\)\?';          then echo "Key dilution should have been 10000."; exit 1; fi
if ! echo "$OUTPUT" | grep -q 'Participation ID:[[:space:]]*[[:alnum:]]\{52\}'; then echo "There should be a participation ID.";  exit 1; fi

# Test multiple data directory supported
NUM_OUTPUT_1=$(echo "$OUTPUT"|grep -c 'Participation ID')
OUTPUT=$(goal account partkeyinfo -d "$ALGORAND_DATA" -d "$ALGORAND_DATA2")
NUM_OUTPUT_2=$(echo "$OUTPUT"|grep -c 'Participation ID')
if (( "$NUM_OUTPUT_2" <= "$NUM_OUTPUT_1" )); then echo "Should have found more participation keys when checking both data directories."; exit 1; fi

# get stderr from this one
OUTPUT=$(goal account listpartkeys -d "$ALGORAND_DATA" -d "$ALGORAND_DATA2" 2>&1)
EXPECTED_ERR="Only one data directory can be specified for this command."
if [[ "$OUTPUT" != "$EXPECTED_ERR" ]]; then echo -e "Unexpected output from multiple data directories with 'listpartkeys': \n$OUTPUT"; exit 1; fi

create_and_fund_account () {
  local TEMP_ACCT=$(${gcmd} account new|awk '{ print $6 }')
  ${gcmd} clerk send -f "$INITIAL_ACCOUNT" -t "$TEMP_ACCT" -a 1000000 > /dev/null
  echo "$TEMP_ACCT"
}

# given key should be installed and have the expected yes/no state
# $1 - yes or no
# $2 - a participation id
# $3 - error message
verify_registered_state () {
  # look for participation ID anywhere in the partkeyinfo output
  if ! goal account partkeyinfo | grep -q "$2"; then
    fail_test "Key was not installed properly: $3"
  fi

  # looking for yes/no, and the 8 character head of participation id in this line:
  # yes         LFMT...RHJQ  4UPT6AQC...               4            0     3000
  if ! goal account listpartkeys | grep -q "$1.*$(echo "$2" | cut -c1-8)\.\.\."; then
    fail_test "Unexpected key state: $3"
  fi
}

# goal account installpartkey
# install manually generated participation keys (do not register)
NEW_ACCOUNT_1=$(create_and_fund_account)
algokey part generate --keyfile test_partkey --first 0 --last 3000 --parent "$NEW_ACCOUNT_1"
PARTICIPATION_ID_1=$(goal account installpartkey --delete-input --partkey test_partkey|awk '{ print $7 }')
verify_registered_state "no" "$PARTICIPATION_ID_1" "goal account installpartkey"

# goal account addpartkey
# generate and install participation keys (do not register)
NEW_ACCOUNT_2=$(create_and_fund_account)
PARTICIPATION_ID_2=$(goal account addpartkey -a "$NEW_ACCOUNT_2" --roundFirstValid 0 --roundLastValid 3000|awk '{ print $7 }')
verify_registered_state "no" "$PARTICIPATION_ID_2" "goal account addpartkey"

# goal account renewpartkeys
# generate, install, and register
NEW_ACCOUNT_3=$(create_and_fund_account)
PARTICIPATION_ID_3=$(${gcmd} account renewpartkey --roundLastValid 3000 -a "$NEW_ACCOUNT_3"|tail -n 1|awk '{ print $7 }')
verify_registered_state "yes" "$PARTICIPATION_ID_3" "goal account renewpartkey"

# goal account changeonlinstatus (--account)
verify_registered_state "no" "$PARTICIPATION_ID_1" "goal account installpartkey (before)"
${gcmd} account changeonlinestatus -a "$NEW_ACCOUNT_1"
verify_registered_state "yes" "$PARTICIPATION_ID_1" "goal account installpartkey (after)"

# goal account renewallpartkeys
# goal account changeonlinstatus (--partkey)
# These do not work as I expected them to. Do they work? I don't know, we should try to remove it.
