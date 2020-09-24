#!/usr/bin/env bash

set -ex

echo "[$0] Testing network string in genesis.json"

# We're looking for a line that looks like the following:
#
#       "network": "mainnet",
#
if ! grep -F "\"network\": \"$NETWORK\"" genesis.json
then
    echo "[$0] The network $NETWORK set in \`genesis.json\` is incorrect."
    exit 1
fi

