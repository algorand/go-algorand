#!/usr/bin/env bash

# The main purpose of this script is to map default network for STABLE builds to MAINNET and not TESTNET

NETWORK=$1

if [ -z "${NETWORK}" ]; then
    echo "Network name required: eg 'compute_branch_release_network.sh mainnet'"
    exit -1
fi

if [ "${NETWORK}" = "testnet" ]; then
    echo "mainnet"
    exit 0
fi

echo "${NETWORK}"
