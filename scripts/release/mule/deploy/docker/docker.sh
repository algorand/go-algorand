#!/usr/bin/env bash
#
# mainnet and testnet are pushed:
#   ./docker.sh mainnet 2.0.6
#
# For betanet:
#   ./docker.sh betanet
#
set -ex

NETWORK=${NEWORK:-mainnet}
VERSION=${VERSION:-latest}

if [[ ! "$NETWORK" =~ ^mainnet$|^testnet$|^betanet$ ]]
then
    echo "[$0] Network values must be either \`mainnet\`, \`testnet\` or \`betanet\`."
    exit 1
fi

pushd docker/releases

if [ "$NETWORK" = mainnet ]
then
    # Build and push mainnet.
   ./build_releases.sh

    # Build and push testnet.
   ./build_releases.sh --network testnet

    if [ -z "$VERSION" ]
    then
        echo "[$0] No version specified."
        exit 1
    fi

   ./build_releases.sh --tagname "$VERSION"
elif [ "$NETWORK" = betanet ]
then
   ./build_releases.sh --network betanet
fi

popd

