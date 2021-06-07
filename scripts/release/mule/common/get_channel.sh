#!/usr/bin/env bash

NETWORK="$1"

if [ "$NETWORK" = betanet ]
then
    echo beta
elif [ "$NETWORK" = mainnet ] || [ "$NETWORK" = testnet ]
then
    echo stable
elif [ "$TRAVIS_BRANCH" = 'rel/nightly' ]
then
    # The rel/nightly branch is only the nightly channel
    echo nightly
else
    echo dev
fi

