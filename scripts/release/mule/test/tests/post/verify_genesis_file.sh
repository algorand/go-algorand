#!/usr/bin/env bash

set -ex

echo "[$0] Testing network string in genesis.json"

# We're looking for a line that looks like the following:
#
#       "network": "mainnet",
#

GEN_FILE=/var/lib/algorand/genesis.json
cd "./tmp/node_pkgs/$OS_TYPE/$ARCH_TYPE"

if [ ! -f "$GEN_FILE" ]
then
    echo "[$0] The genesis file is not present."
    exit 1
fi

EXPECTED_NETWORK=$(jq -r '.network' $GEN_FILE)

if [ "$NETWORK" != "$EXPECTED_NETWORK" ]
then
    echo "[$0] The network value \`$NETWORK\` in \`$GEN_FILE\` is incorrect, it does not match $EXPECTED_NETWORK."
    exit 1
fi

echo "[$0] The network value \`$NETWORK\` in \`$GEN_FILE\` is correct."

