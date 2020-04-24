#!/usr/bin/env bash

set -ex

CHANNEL="$1"
VERSION="$2"

if [ -z "$CHANNEL" ] || [ -z "$VERSION" ]; then
    echo "CHANNEL=$CHANNEL and VERSION=$VERSION variables must be defined."
    exit 1
fi

# Path is relative to the root of the Jenkins workspace.
RSTAMP=$(./scripts/release/prod/reverse_hex_timestamp)

if ! aws s3 sync "s3://algorand-builds/$CHANNEL/$VERSION" "s3://algorand-releases/$CHANNEL/${RSTAMP}_${VERSION}"; then
    echo There was a problem syncing the staging and production buckets!
    exit 1
fi

