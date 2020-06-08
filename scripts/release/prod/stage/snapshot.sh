#!/usr/bin/env bash

set -ex

CHANNEL="$1"
VERSION="$2"

if [ -z "$CHANNEL" ] || [ -z "$VERSION" ]; then
    echo "CHANNEL=$CHANNEL and VERSION=$VERSION variables must be defined."
    exit 1
fi

echo
date "+build_release begin SNAPSHOT stage %Y%m%d_%H%M%S"
echo

DEBS_DIR="$HOME/packages/deb/$CHANNEL"
DEB="algorand_${CHANNEL}_linux-amd64_${VERSION}.deb"

aws s3 cp "s3://algorand-staging/releases/$CHANNEL/$VERSION/$DEB" .
mv "$DEB" "$DEBS_DIR"

aptly repo add algorand "$DEBS_DIR"
aptly snapshot create "${CHANNEL}-${VERSION}" from repo algorand

# Note: only run the first command below if there is nothing published.
#aptly -config="$HOME"/.aptly.conf publish snapshot -gpg-key=dev@algorand.com -origin=Algorand -label=Algorand "${CHANNEL}-${VERSION}" "s3:ben-test-2.0.3:"

# Since snapshots have already been published, it's only necessary to switch the old one for the new one.
aptly -config="$HOME"/.aptly.conf -gpg-key=dev@algorand.com publish switch "$CHANNEL" "s3:algorand-releases:" "$SNAPSHOT"

#"${HOME}"/go/src/github.com/algorand/go-algorand/scripts/release/prod/rpm/run_centos.sh

echo
date "+build_release end SNAPSHOT stage %Y%m%d_%H%M%S"
echo

