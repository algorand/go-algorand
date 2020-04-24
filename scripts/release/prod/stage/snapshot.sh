#!/usr/bin/env bash

echo
date "+build_release begin SNAPSHOT stage %Y%m%d_%H%M%S"
echo

set -ex

CHANNEL="$1"
VERSION="$2"

if [ -z "$CHANNEL" ] || [ -z "$VERSION" ]; then
    echo "CHANNEL=$CHANNEL and VERSION=$VERSION variables must be defined."
    exit 1
fi

DEBS_DIR="$HOME/packages/deb/$CHANNEL"
DEB="algorand_${CHANNEL}_linux-amd64_${VERSION}.deb"

aws s3 cp "s3://algorand-builds/channel/$CHANNEL/$DEB" .
mv "$DEB" "$DEBS_DIR"

aptly repo add algorand "$DEBS_DIR/*.deb"
aptly snapshot create "${CHANNEL}-${VERSION}" from repo algorand
aptly publish switch stable "s3:algorand-releases" "${CHANNEL}-${VERSION}"

"${HOME}"/go/src/github.com/algorand/go-algorand/scripts/release/prod/rpm/run_centos.sh

echo
date "+build_release end SNAPSHOT stage %Y%m%d_%H%M%S"
echo

