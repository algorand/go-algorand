#!/usr/bin/env bash

set -ex

if [ $# -lt 2 ]
then
    echo "Usage: $0 CHANNEL VERSION"
    exit 1
fi

#ARCH_BIT=$(uname -m)
#ARCH_TYPE=$(./scripts/archtype.sh)
#OS_TYPE=$(./scripts/ostype.sh)
#VERSION=${VERSION:-$(./scripts/compute_build_number.sh -f)}
#BRANCH=${BRANCH:-$(git rev-parse --abbrev-ref HEAD)}
#CHANNEL=${CHANNEL:-$(./scripts/compute_branch_channel.sh "$BRANCH")}
#PKG_DIR="./tmp/node_pkgs/$OS_TYPE/$ARCH_TYPE"
#SIGNING_KEY_ADDR=dev@algorand.com

CHANNEL="$1"
VERSION="$2"
REPO=algorand
SNAPSHOT=${3:-"$CHANNEL-$VERSION"}
PKG_DIR="$HOME/packages/deb/$CHANNEL"

if [ "$CHANNEL" = beta ]
then
    REPO=algorand-beta
elif [ "$CHANNEL" = indexer ]
then
    REPO=algorand-indexer
fi

aws s3 cp "s3://algorand-staging/releases/$CHANNEL/$VERSION/algorand_${CHANNEL}_linux-amd64_${VERSION}.deb" "$PKG_DIR"

aptly repo add "$REPO" "$PKG_DIR/"*.deb
aptly snapshot create "$SNAPSHOT" from repo "$REPO"
aptly publish switch "$CHANNEL" s3:algorand-releases: "$SNAPSHOT"
#aptly publish snapshot -gpg-key=dev@algorand.com -origin=Algorand -label=Algorand "$SNAPSHOT" s3:algorand-releases:

