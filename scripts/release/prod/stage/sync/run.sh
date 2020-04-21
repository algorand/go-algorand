#!/usr/bin/env bash
# shellcheck disable=2029

set -ex

trap 'bash ./scripts/release/common/ec2/shutdown.sh' ERR

# Path(s) are relative to the root of the Jenkins workspace.
STAGING="$1"
PROD="$2"
RSTAMP=$(scripts/release/prod/reverse_hex_timestamp)

BUILD_ENV=$(ssh -i ReleaseBuildInstanceKey.pem -o -A ubuntu@"$INSTANCE" cat build_env)
CHANNEL=$(sed -n 's/.*CHANNEL=\(.*\)/\1/p' <<< "$BUILD_ENV")
RELEASE=$(sed -n 's/.*FULLVERSION=\(.*\)/\1/p' <<< "$BUILD_ENV")

if ! aws s3 sync s3://"$STAGING"/"$CHANNEL"/"$RELEASE" s3://"$PROD"/"$CHANNEL"/"$RSTAMP"_"$RELEASE"
then
    echo There was a problem syncing the staging and production buckets!
    exit 1
fi

