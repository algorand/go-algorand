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

KEY_PREFIX="$CHANNEL/$VERSION"
FILENAME_SUFFIX="${CHANNEL}_linux-amd64_${VERSION}.deb"
ALGORAND_KEY="$KEY_PREFIX/algorand_${FILENAME_SUFFIX}"
DEVTOOLS_KEY="$KEY_PREFIX/algorand-devtools_${FILENAME_SUFFIX}"

# `STAGING` could contain a "path" (i.e. "my_bucket/foo/bar"), but the
# `s3api` api expects it to be only the bucket name (i.e., "my_bucket").
BUCKET=$(awk -F/ '{ print $1 }' <<< "$STAGING")

# If the strings match then the objects are in the top-level of the bucket.
if [ "$STAGING" = "$BUCKET" ]
then
    BUCKET_PREFIX_PATH="$STAGING"
else
    # Remove matching prefix.
    BUCKET_PREFIX_PATH=${STAGING#$BUCKET"/"}
fi

for key in {"$ALGORAND_KEY","$DEVTOOLS_KEY"}
do
    key="$BUCKET_PREFIX_PATH/$key"
    if aws s3api head-object --bucket "$BUCKET" --key "$key"
    then
        aws s3 cp "s3://$BUCKET/$key" "$PACKAGES_DIR"
    else
        echo "[$0] The package \`$key\` failed to download."
    fi
done

if ls -A $PACKAGES_DIR
then
    aptly repo add "$CHANNEL" "$PACKAGES_DIR"/*.deb
    aptly repo show -with-packages "$CHANNEL"
    aptly snapshot create "$SNAPSHOT" from repo "$CHANNEL"
    if ! aptly publish show "$CHANNEL" s3:algorand-releases: &> /dev/null
    then
        aptly publish snapshot -gpg-key=dev@algorand.com -origin=Algorand -label=Algorand "$SNAPSHOT" s3:algorand-releases:
    else
        aptly publish switch "$CHANNEL" s3:algorand-releases: "$SNAPSHOT"
    fi
else
    echo "[$0] The packages directory is empty, so there is nothing to add the \`$CHANNEL\` repo."
    exit 1
fi

