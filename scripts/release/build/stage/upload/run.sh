#!/usr/bin/env bash

# Path(s) are relative to the root of the Jenkins workspace.

CHANNEL="$1"
BUCKET_LOCATION="$2"
RSTAMP="$3"
FULLVERSION="$4"
INSTANCE=$(cat scripts/release/tmp/instance)

rm -rf pkg/* && mkdir -p pkg/"$FULLVERSION"
ssh -i ReleaseBuildInstanceKey.pem -A ubuntu@"$INSTANCE" bash ben-branch/scripts/release/build/stage/upload/task.sh
scp -i ReleaseBuildInstanceKey.pem -o StrictHostKeyChecking=no -r ubuntu@"$INSTANCE":~/node_pkg/* pkg/"$FULLVERSION"/
# Create the buildlog file.
scp -i ReleaseBuildInstanceKey.pem -o StrictHostKeyChecking=no ubuntu@"$INSTANCE":~/build_status_"$CHANNEL"_*.asc.gz pkg/
aws s3 sync --exclude dev* --exclude master* --exclude nightly* --exclude stable* --acl public-read pkg/"$FULLVERSION" "$BUCKET_LOCATION"/"$CHANNEL"/"$FULLVERSION"/

#ssh -i ReleaseBuildInstanceKey.pem -A ubuntu@"$INSTANCE" bash go/src/github.com/algorand/go-algorand/scripts/release/upload.sh

#aws s3 cp --quiet node_pkg/build_status_"$CHANNEL"_*.asc.gz s3://algorand-devops-misc/buildlog/"$FULLVERSION"/

