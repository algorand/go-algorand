#!/usr/bin/env bash

if [[ $1 == "" ]]
then
   ALGORAND_NETWORK="testnet"
else
   ALGORAND_NETWORK=$1
fi

if [[ ${ALGORAND_NETWORK} != "betanet" && ${ALGORAND_NETWORK} != "devnet" && ${ALGORAND_NETWORK} != "testnet" && ${ALGORAND_NETWORK} != "mainnet"  ]]
then
    echo "error, unrecognized network: ${ALGORAND_NETWORK}, please specify one of: betanet, devnet, testnet, mainnet"
    exit
fi

CHANNEL_VERSION="%CHANNEL_VERSION%"
ALGORAND_CONTAINER="algod_${CHANNEL_VERSION}_${ALGORAND_NETWORK}"
ALGORAND_VOLUME="algod-data-${ALGORAND_NETWORK}"
ALGORAND_IMAGE="algorand/algod_${CHANNEL_VERSION}:latest"

echo "starting container '${ALGORAND_CONTAINER}' with volume: '${ALGORAND_VOLUME}'"

docker run --name ${ALGORAND_CONTAINER} -d -e ALGORAND_NETWORK=${ALGORAND_NETWORK} --mount type=volume,source=${ALGORAND_VOLUME},dst=/root/node/data -t ${ALGORAND_IMAGE}

dockerRunStatus=$?
if [ $dockerRunStatus -ne 0 ]; then
    echo "Error: $dockerRunStatus"
else
    echo "docker container '${ALGORAND_CONTAINER}' started successfully"
    echo "you can attach to the running container with the following command:"
    echo "   docker exec -it  ${ALGORAND_CONTAINER} /bin/bash"
fi
exit $dockerRunStatus


