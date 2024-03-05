#!/usr/bin/env bash

set -ex

CHANNEL=${CHANNEL:-$("./scripts/release/mule/common/get_channel.sh" "$NETWORK")}
VERSION=${VERSION:-$(./scripts/compute_build_number.sh -f)}
PACKAGES_DIR=${PACKAGES_DIR:-~/packages}
SNAPSHOT=${SNAPSHOT:-"${CHANNEL}-${VERSION}"}

mkdir -p $PACKAGES_DIR
rm -f $PACKAGES_DIR/*.deb

aptly mirror update stable
aptly mirror update beta

# aptly repo import <src-mirror> <dst-repo> <package-query> ...
aptly repo import stable stable algorand algorand-devtools
aptly repo import beta beta algorand-beta algorand-devtools-beta

cp -f tmp/{algorand,algorand-devtools}_${CHANNEL}_linux-{amd64,arm64}_${VERSION}.deb $PACKAGES_DIR

if ls -A $PACKAGES_DIR
then
    aptly repo add "$CHANNEL" "$PACKAGES_DIR"/*.deb
    aptly repo show -with-packages "$CHANNEL"
    aptly snapshot create "$SNAPSHOT" from repo "$CHANNEL"
    if ! aptly publish show "$CHANNEL" s3:algorand-releases: &> /dev/null
    then
        aptly publish -batch snapshot -gpg-key=dev@algorand.com -origin=Algorand -label=Algorand "$SNAPSHOT" s3:algorand-releases:
    else
        aptly publish switch "$CHANNEL" s3:algorand-releases: "$SNAPSHOT"
    fi
else
    echo "[$0] The packages directory is empty, so there is nothing to add the \`$CHANNEL\` repo."
    exit 1
fi
