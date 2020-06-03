#!/usr/bin/env bash

set -ex

CHANNEL="$1"
VERSION="$2"

if [ -z "$CHANNEL" ] || [ -z "$VERSION" ]; then
    echo "CHANNEL=$CHANNEL and VERSION=$VERSION variables must be defined."
    exit 1
fi

RSTAMP=$(./scripts/release/prod/reverse_hex_timestamp)

if ! aws s3 sync --exclude="*" --include="*$VERSION*" "s3://algorand-staging/releases/$CHANNEL/$VERSION/" "s3://algorand-dev-deb-repo/releases/$CHANNEL/${RSTAMP}_${VERSION}"; then
    echo There was a problem syncing the staging and production buckets!
    exit 1
fi

