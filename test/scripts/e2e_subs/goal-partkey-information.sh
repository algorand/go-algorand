#!/usr/bin/env bash
# TIMEOUT=300

# errors are handled manually, so no -e
set -x

date "+$0 start %Y%m%d_%H%M%S"

# Registered  Account      ParticipationID   Last Used  First round  Last round
# yes         LFMT...RHJQ  4UPT6AQC...               4            0     3000000
OUTPUT=$(goal account listpartkeys|tail -n 1|tr -s ' ')
if [[ "$OUTPUT"                          != yes*    ]]; then echo "Registered should be 'yes' but wasn't.";   exit 1; fi
if [[ $(echo "$OUTPUT" | cut -d' ' -f 4) == 0       ]]; then echo "Last Used shouldn't be 0 but was.";        exit 1; fi
if [[ $(echo "$OUTPUT" | cut -d' ' -f 5) != 0       ]]; then echo "First round should be 0 but wasn't.";      exit 1; fi
if [[ $(echo "$OUTPUT" | cut -d' ' -f 6) != 3000000 ]]; then echo "Last round should be 3000000 but wasn't."; exit 1; fi

#Dumping participation key info from /tmp/tmpwtomya9x/net/Node...
#
#Participation ID:          4UPT6AQCFZU5ZDN3WKVPCFYOH2SFJ7SPHK7XPWI2CIDYKK7K3WMQ
#Parent address:            LFMTCXCY6WGSFSGLSNTFH532KVERJVNRD7W5H7GIQ4MPGM7SSVYMQYRHJQ
#Last vote round:           3
#Last block proposal round: 4
#Effective first round:     0
#Effective last round:      3000000
#First round:               0
#Last round:                3000000
#Key dilution:              10000
#Selection key:             esIsBJB86P+sLeqO3gVoLBGfpuwYlWN4lNzz2AYslTo=
#Voting key:                W1OcXLZsaATyOd5FbhRgXHmcywvn++xEVUAQ0NejmW4=
OUTPUT=$(goal account partkeyinfo)
if ! echo "$OUTPUT" | grep -q 'First round:[[:space:]]* 0';                     then echo "First round should have been 0.";                exit 1; fi
if ! echo "$OUTPUT" | grep -q 'Last round:[[:space:]]* 3000000';                then echo "Last round should have been 3000000.";           exit 1; fi
if ! echo "$OUTPUT" | grep -q 'Effective last round:[[:space:]]* 3000000';      then echo "Effective last round should have been 3000000."; exit 1; fi
# 100 or 10000 due to arm64 bug
if ! echo "$OUTPUT" | grep -q 'Key dilution:[[:space:]]* 100\(00\)\?';            then echo "Key dilution should have been 10000.";           exit 1; fi
if ! echo "$OUTPUT" | grep -q 'Participation ID:[[:space:]]*[[:alnum:]]\{52\}'; then echo "There should be a participation ID.";            exit 1; fi

# Test multiple data directory supported
OUTPUT=$(goal account partkeyinfo -d "$ALGORAND_DATA" -d "$ALGORAND_DATA2"|grep -c 'Participation ID')
if [[ "$OUTPUT" != "2" ]]; then echo "Two Participation IDs should have been found."; exit 1; fi

# get stderr from this one
OUTPUT=$(goal account listpartkeys -d "$ALGORAND_DATA" -d "$ALGORAND_DATA2" 2>&1)
EXPECTED_ERR="Only one data directory can be specified for this command."
if [[ "$OUTPUT" != "$EXPECTED_ERR" ]]; then echo -e "Unexpected output from multiple data directories with 'listpartkeys': \n$OUTPUT"; exit 1; fi
