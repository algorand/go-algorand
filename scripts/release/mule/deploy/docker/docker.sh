#!/usr/bin/env bash
#
# mainnet and testnet are pushed:
#   ./docker.sh mainnet 2.0.6
#
# For betanet:
#   ./docker.sh betanet
#
set -ex

NETWORK="$1"
VERSION="$2"

RED_FG=$(tput setaf 1 2>/dev/null)
END_FG_COLOR=$(tput sgr0 2>/dev/null)

if [[ ! "$NETWORK" =~ ^mainnet$|^testnet$|^betanet$ ]]
then
    echo "$RED_FG[$0]$END_FG_COLOR Network values must be either \`mainnet\`, \`testnet\` or \`betanet\`."
    exit 1
fi

pushd "$HOME/projects/go-algorand/docker/releases"

if [ "$NETWORK" = mainnet ]
then
    # Build and push mainnet.
   ./build_releases.sh

    # Build and push testnet.
   ./build_releases.sh --network testnet

    if [ -z "$VERSION" ]
    then
        echo "$RED_FG[$0]$END_FG_COLOR No version specified."
        exit 1
    fi

   ./build_releases.sh --tagname "$VERSION"
elif [ "$NETWORK" = betanet ]
then
   ./build_releases.sh --network betanet
fi

popd

