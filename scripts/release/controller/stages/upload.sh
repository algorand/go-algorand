#!/usr/bin/env bash

# Path(s) are relative to the root of the Jenkins workspace.

CHANNEL="$1"
BUCKET_LOCATION="$2"
RSTAMP="$3"
FULLVERSION="$4"
INSTANCE=$(cat scripts/release/tmp/instance)

rm -rf node_pkg/* && mkdir -p node_pkg/"$RSTAMP"
scp -i ReleaseBuildInstanceKey.pem -o StrictHostKeyChecking=no -r ubuntu@"$INSTANCE":~/node_pkg/* node_pkg/"$RSTAMP"/
aws s3 sync --exclude dev* --exclude master* --exclude nightly* --exclude stable* --acl public-read node_pkg/"$RSTAMP" "$BUCKET_LOCATION"/"$CHANNEL"/"$RSTAMP"_"$FULLVERSION"/

# Create the buildlog file.
ssh -i ReleaseBuildInstanceKey.pem -A ubuntu@"$INSTANCE" bash go/src/github.com/algorand/go-algorand/scripts/release/controller/upload.sh
# sh "aws s3 cp --quiet ubuntu@\$(cat scripts/release/tmp/instance)/build_status_$CHANNEL_${FULLVERSION}.asc.gz s3://algorand-devops-misc/buildlog/${RSTAMP}/"
scp -i ReleaseBuildInstanceKey.pem -o StrictHostKeyChecking=no ubuntu@"$INSTANCE":~/build_status_"$CHANNEL"_*.asc.gz node_pkg/
aws s3 cp --quiet node_pkg/build_status_"$CHANNEL"_*.asc.gz s3://algorand-devops-misc/buildlog/"$RSTAMP"/

