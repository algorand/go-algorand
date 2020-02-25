#!/usr/bin/env bash

set -ex

trap 'bash ./scripts/release/common/ec2/shutdown.sh' ERR

# Path(s) are relative to the root of the Jenkins workspace.

#BUCKET_LOCATION="$2"
INSTANCE=$(cat scripts/release/common/ec2/tmp/instance)
BUILD_ENV=$(ssh -i ReleaseBuildInstanceKey.pem -A ubuntu@"$INSTANCE" cat /home/ubuntu/build_env)
CHANNEL=$(sed -n 's/.*CHANNEL=\(.*\)/\1/p' <<< "$BUILD_ENV")
FULLVERSION=$(sed -n 's/.*FULLVERSION=\(.*\)/\1/p' <<< "$BUILD_ENV")

rm -rf pkg && mkdir -p pkg/"$FULLVERSION"

#ssh -i ReleaseBuildInstanceKey.pem -A ubuntu@"$INSTANCE" bash go/src/github.com/algorand/go-algorand/scripts/release/build/stage/upload/task.sh
ssh -i ReleaseBuildInstanceKey.pem -A ubuntu@"$INSTANCE" bash ben-branch/scripts/release/build/stage/upload/task.sh
scp -i ReleaseBuildInstanceKey.pem -o StrictHostKeyChecking=no -r ubuntu@"$INSTANCE":~/node_pkg/* pkg/"$FULLVERSION"/

#aws s3 sync --exclude dev* --exclude master* --exclude nightly* --exclude stable* --acl public-read pkg/"$FULLVERSION" s3://"$BUCKET_LOCATION"/"$CHANNEL"/"$FULLVERSION"/
aws s3 sync --exclude dev* --exclude master* --exclude nightly* --exclude stable* --acl public-read pkg/"$FULLVERSION" s3://ben-test-2.0.3/"$CHANNEL"/"$FULLVERSION"/

