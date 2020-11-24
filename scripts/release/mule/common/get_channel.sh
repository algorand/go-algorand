#!/usr/bin/env bash

NETWORK="$1"

if [ "$NETWORK" = betanet ]
then
    echo stable
elif [ "$NETWORK" = devnet ]
then
    echo dev
else
    # mainnet, testnet
    echo stable
fi

