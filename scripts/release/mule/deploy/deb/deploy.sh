#!/usr/bin/env bash

set -ex

if [ -z "$NETWORK" ]
then
    echo "[$0] Network is a required parameter."
    exit 1
fi

if [ -z "$STAGING" ]
then
    echo "[$0] Staging is a required parameter."
    exit 1
fi

CHANNEL=$("./scripts/release/mule/common/get_channel.sh" "$NETWORK")
VERSION=${VERSION:-$(./scripts/compute_build_number.sh -f)}

if [ -z "$SNAPSHOT" ]
then
    SNAPSHOT="$CHANNEL-$VERSION"
fi

PACKAGES_DIR=/root/packages
mkdir -p /root/packages

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
