#!/usr/bin/env bash

set -e

if [ -z "$STAGING" ]
then
    echo "[$0] Staging is a required parameter."
    exit 1
fi

if [ -z "$CHANNEL" ]
then
    echo "[$0] Channel is a required parameter."
    exit 1
fi

if [[ ! "$CHANNEL" =~ ^beta$|^stable$ ]]
then
    echo "[$0] Repository values must be either \`beta\` or \`stable\`."
    exit 1
fi

if [ -z "$VERSION" ]
then
    echo "[$0] Version is a required parameter."
    exit 1
fi

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

KEY_PREFIX="releases/$CHANNEL/$VERSION"
FILENAME_SUFFIX="${CHANNEL}_linux-amd64_${VERSION}.deb"
ALGORAND_KEY="$KEY_PREFIX/algorand_${FILENAME_SUFFIX}"
DEVTOOLS_KEY="$KEY_PREFIX/algorand-devtools_${FILENAME_SUFFIX}"

for key in {"$ALGORAND_KEY","$DEVTOOLS_KEY"}
do
    if aws s3api head-object --bucket "$STAGING" --key "$key"
    then
        aws s3 cp "s3://$STAGING/$key" "$PACKAGES_DIR"
    else
        echo "[$0] The package \`$key\` failed to download."
    fi
done

if ls -A $PACKAGES_DIR
then
    aptly repo add "$CHANNEL" "$PACKAGES_DIR"/*.deb
    aptly repo show -with-packages "$CHANNEL"
    aptly snapshot create "$SNAPSHOT" from repo "$CHANNEL"
    aptly publish snapshot -gpg-key=dev@algorand.com -origin=Algorand -label=Algorand "$SNAPSHOT" s3:algorand-releases:
else
    echo "[$0] The packages directory is empty, so there is nothing to add the \`$CHANNEL\` repo."
    exit 1
fi

