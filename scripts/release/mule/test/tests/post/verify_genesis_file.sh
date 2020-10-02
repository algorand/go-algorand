#!/usr/bin/env bash

set -e

echo "[$0] Testing network string in genesis.json"

# We're looking for a line that looks like the following:
#
#       "network": "mainnet",
#

cd "./tmp/node_pkgs/$OS_TYPE/$ARCH_TYPE"

if [ ! -f /var/lib/algorand/genesis.json ]
then
    echo "[$0] The genesis file is not present."
    exit 1
fi

if ! grep -F "\"network\": \"$NETWORK\"" /var/lib/algorand/genesis.json
then
    echo "[$0] The network \`$NETWORK\` set in \`genesis.json\` is incorrect."
    exit 1
fi

echo "[$0] The network \`$NETWORK\` set in \`genesis.json\` is correct."

