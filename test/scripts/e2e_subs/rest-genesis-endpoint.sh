#!/usr/bin/env bash
# TIMEOUT=300

my_dir="$(dirname "$0")"
#"$my_dir/rest.sh" "$@"
source "$my_dir/rest.sh" "$@"

date "+$0 start %Y%m%d_%H%M%S"

call_and_verify "There should be a genesis endpoint." "/genesis" 200 '
  "id": "v1",
  "network": "tbd",
  "proto": "future",
  "rwd": "7777777777777777777777777777777777777777777777777774MSJUVU"
}'
