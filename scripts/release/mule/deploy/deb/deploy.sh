#!/usr/bin/env bash

set -ex

if [ $# -lt 3 ]
then
    echo "Usage: $0 PROJECT CHANNEL VERSION"
    exit 1
fi

PROJECT="$1"
CHANNEL="$2"
VERSION="$3"
SNAPSHOT="$4"
REPO=algorand
FILENAME_PREFIX="$REPO"

if [ "$PROJECT" = indexer ]
then
    echo abort
    exit 1
fi

PKG_DIR="$HOME/packages-test/deb/$PROJECT/$CHANNEL"

if [ "$PROJECT" != algorand ]
then
    REPO="$REPO-$PROJECT"
    FILENAME_PREFIX="$REPO"
fi

if [ "$CHANNEL" = beta ]
then
    REPO="$REPO-beta"
fi

if [ -z "$SNAPSHOT" ]
then
    SNAPSHOT="$REPO-$VERSION"
fi

echo -e "PROJECT $PROJECT\nREPO $REPO\nSNAPSHOT $SNAPSHOT\nFILENAME_PREFIX $FILENAME_PREFIX"

aws s3 cp "s3://algorand-staging/releases/$CHANNEL/$VERSION/${FILENAME_PREFIX}_${CHANNEL}_linux-amd64_${VERSION}.deb" "$PKG_DIR"

#aptly repo create -distribution="devtools" -architectures="amd64" -component="main" -comment="devtools-stable" algorand-devtools
#aptly repo create -distribution="devtools-beta" -architectures="amd64" -component="main" -comment="devtools-beta" algorand-devtools-beta

aptly repo add "$REPO" "$PKG_DIR/"*.deb
aptly snapshot create "$SNAPSHOT" from repo "$REPO"
#aptly publish snapshot -gpg-key=dev@algorand.com -origin=Algorand -label=Algorand "$SNAPSHOT" s3:algorand-releases:
aptly publish switch "$CHANNEL" s3:algorand-releases: "$SNAPSHOT"

