#!/usr/bin/env bash

NETWORK="$1"

if [ "$NETWORK" = betanet ]
then
    echo beta
elif [ "$NETWORK" = mainnet ] || [ "$NETWORK" = testnet ]
then
    echo stable
else
    echo dev
fi

