#!/usr/bin/env bash
# shellcheck disable=2029

# Path(s) are relative to the root of the Jenkins workspace.
STAGING="$1"
PROD="$2"
CHANNEL="$3"
RELEASE="$4"
RSTAMP=$(./scripts/release/prod/reverse_hex_timestamp)

if ! aws s3 sync s3://"$STAGING"/"$CHANNEL"/"$RELEASE" s3://"$PROD"/"$CHANNEL"/"$RSTAMP"_"$RELEASE"
then
    echo There was a problem syncing the staging and production buckets!
    exit 1
fi

