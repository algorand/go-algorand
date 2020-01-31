#!/usr/bin/env bash

# Path(s) are relative to the root of the Jenkins workspace.

CHANNEL="$1"
BUCKET_LOCATION="$2"
FULLVERSION="$3"
INSTANCE=$(cat scripts/release/tmp/instance)

rm -rf pkg/* && mkdir -p pkg/"$FULLVERSION"
ssh -i ReleaseBuildInstanceKey.pem -A ubuntu@"$INSTANCE" bash go/src/github.com/algorand/go-algorand/scripts/release/ci/upload.sh
scp -i ReleaseBuildInstanceKey.pem -o StrictHostKeyChecking=no -r ubuntu@"$INSTANCE":~/node_pkg/* pkg/"$FULLVERSION"/
# Create the buildlog file.
scp -i ReleaseBuildInstanceKey.pem -o StrictHostKeyChecking=no ubuntu@"$INSTANCE":~/build_status_"$CHANNEL"_*.asc.gz pkg/
aws s3 sync --exclude dev* --exclude master* --exclude nightly* --exclude stable* --acl public-read pkg/"$FULLVERSION" "$BUCKET_LOCATION"/"$CHANNEL"/"$FULLVERSION"/

