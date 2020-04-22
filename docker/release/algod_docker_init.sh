#!/usr/bin/env bash

GENESIS_FILE="/root/node/data/genesis.json"
CONFIG_FILE="/root/node/data/config.json"

echo "initializing docker container for algod network: '${ALGORAND_NETWORK}'"

if [[ ${ALGORAND_NETWORK} != "betanet" &&  ${ALGORAND_NETWORK} != "devnet" && ${ALGORAND_NETWORK} != "testnet" && ${ALGORAND_NETWORK} != "mainnet"  ]]
then
    echo "error, unrecognized network: ${ALGORAND_NETWORK}, please specify one of: betanet, devnet, testnet, mainnet"
    echo "defaulting to: 'testnet'"
    ALGORAND_NETWORK="testnet"
fi


if [[ -f "${GENESIS_FILE}" ]]; then
    echo "genesis file exist: '${GENESIS_FILE}'"
else
    echo "setting up genesis file: '${GENESIS_FILE}' for network '${ALGORAND_NETWORK}'"
    cp /root/node/genesis/${ALGORAND_NETWORK}/genesis.json /root/node/data/
fi
tail -n 7 ${GENESIS_FILE}

if [[ -f "${CONFIG_FILE}" ]]; then
   echo "config file exist: '${CONFIG_FILE}'"
else
   echo "setting up config file: '${CONFIG_FILE}'"
   cp /root/node/data/config.json.example /root/node/data/config.json
fi

echo "starting algod"
goal node start

sleep 5

echo "algod status"
goal node status

tail -f /dev/null

