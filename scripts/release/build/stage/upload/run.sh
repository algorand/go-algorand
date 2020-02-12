#!/usr/bin/env bash

# Path(s) are relative to the root of the Jenkins workspace.

CHANNEL="$1"
BUCKET_LOCATION="$2"
INSTANCE=$(cat scripts/release/common/ec2/tmp/instance)
FULLVERSION=$(ssh -i ReleaseBuildInstanceKey.pem -A ubuntu@"$INSTANCE" cat ~/fullversion.dat)

rm -rf pkg && mkdir -p pkg/"$FULLVERSION"

ssh -i ReleaseBuildInstanceKey.pem -A ubuntu@"$INSTANCE" bash go/src/github.com/algorand/go-algorand/scripts/release/build/stage/upload/task.sh
scp -i ReleaseBuildInstanceKey.pem -o StrictHostKeyChecking=no -r ubuntu@"$INSTANCE":~/node_pkg/* pkg/"$FULLVERSION"/

# Create the buildlog file.
scp -i ReleaseBuildInstanceKey.pem -o StrictHostKeyChecking=no ubuntu@"$INSTANCE":~/build_status_"$CHANNEL"_*.asc.gz pkg/
aws s3 sync --exclude dev* --exclude master* --exclude nightly* --exclude stable* --acl public-read pkg/"$FULLVERSION" s3://"$BUCKET_LOCATION"/"$CHANNEL"/"$FULLVERSION"/

