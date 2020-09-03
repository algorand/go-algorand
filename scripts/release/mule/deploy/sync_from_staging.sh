#!/usr/bin/env bash

set -ex

if [ $# -ne 2 ]
then
    echo "Usage: $0 CHANNEL VERSION"
    exit 1
fi

CHANNEL=$1
VERSION=$2

aws s3 sync "s3://algorand-staging/releases/$CHANNEL/$VERSION" "s3://algorand-dev-deb-repo/releases/$CHANNEL/$("$HOME/projects/go-algorand/scripts/release/prod/reverse_hex_timestamp")_$VERSION"

