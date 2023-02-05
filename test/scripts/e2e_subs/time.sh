#!/bin/bash

filename=$(basename "$0")
scriptname="${filename%.*}"
date "+${scriptname} start %Y%m%d_%H%M%S"

set -exo pipefail
export SHELLOPTS

# make sure the time is updating
for i in {1..20}; do
  output=$(goal node status)
  if [[ $output != *"Time since last block: 0.0s"* ]]; then
    exit 0
  fi
  sleep 0.5
done

echo "Time since last block is still 0.0s after 10 seconds"
goal node status
exit 1
