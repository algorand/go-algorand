#!/bin/bash

filename=$(basename "$0")
scriptname="${filename%.*}"
date "+${scriptname} start %Y%m%d_%H%M%S"

set -exo pipefail
export SHELLOPTS

WALLET=$1

# make sure the time is updating
for i in {1..20}; do
  TIME=$(goal node status | grep 'Time since last block: '|awk '{ print $5 }')
  if [[ "$TIME" != "0.0s" ]]; then
    return
  fi
  sleep 0.5
done
