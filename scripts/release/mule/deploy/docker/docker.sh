#!/usr/bin/env bash
#
# mainnet and testnet are pushed:
#   ./docker.sh mainnet 2.0.6
#
# For betanet:
#   ./docker.sh betanet
#
set -e

if [ -z "$NETWORK" ] || [ -z "$VERSION" ]; then
    echo "[$0] NETWORK=$NETWORK or VERSION=$VERSION is missing."
    exit 1
fi

if [[ ! "$NETWORK" =~ ^mainnet$|^testnet$|^betanet$ ]]
then
    echo "[$0] Network values must be either \`mainnet\`, \`testnet\` or \`betanet\`."
    exit 1
fi

pushd docker/releases

if [ "$NETWORK" = mainnet ]
then
  # Build and push mainnet.
  ./build_releases.sh --tagname "$VERSION"

  # Build and push testnet.
  ./build_releases.sh --tagname "$VERSION" --network testnet --cached
elif [ "$NETWORK" = betanet ]
then
  ./build_releases.sh --tagname "$VERSION" --network betanet
fi

popd
