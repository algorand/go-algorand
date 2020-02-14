#!/usr/bin/env bash

# Path(s) are relative to the root of the Jenkins workspace.

# This is temporary (taken from `compute_branch_channel.sh`).
if [ "$1" = "master" ]; then
    CHANNEL=master
elif [ "$1" = "rel/nightly" ]; then
    CHANNEL=nightly
elif [ "$1" = "rel/stable" ]; then
    CHANNEL=stable
elif [ "$1" = "rel/beta" ]; then
    CHANNEL=beta
else
    CHANNEL=dev
fi

#BUCKET_LOCATION="$2"
INSTANCE=$(cat scripts/release/common/ec2/tmp/instance)

scp -i ReleaseBuildInstanceKey.pem -o StrictHostKeyChecking=no -r ubuntu@"$INSTANCE":~/fullversion.dat .
FULLVERSION=$(cat fullversion.dat)

rm -rf pkg && mkdir -p pkg/"$FULLVERSION"

#ssh -i ReleaseBuildInstanceKey.pem -A ubuntu@"$INSTANCE" bash go/src/github.com/algorand/go-algorand/scripts/release/build/stage/upload/task.sh
ssh -i ReleaseBuildInstanceKey.pem -A ubuntu@"$INSTANCE" bash ben-branch/scripts/release/build/stage/upload/task.sh
scp -i ReleaseBuildInstanceKey.pem -o StrictHostKeyChecking=no -r ubuntu@"$INSTANCE":~/node_pkg/* pkg/"$FULLVERSION"/

# Create the buildlog file.
scp -i ReleaseBuildInstanceKey.pem -o StrictHostKeyChecking=no ubuntu@"$INSTANCE":~/build_status_"$CHANNEL"_*.asc.gz pkg/
#aws s3 sync --exclude dev* --exclude master* --exclude nightly* --exclude stable* --acl public-read pkg/"$FULLVERSION" s3://"$BUCKET_LOCATION"/"$CHANNEL"/"$FULLVERSION"/
aws s3 sync --exclude dev* --exclude master* --exclude nightly* --exclude stable* --acl public-read pkg/"$FULLVERSION" s3://ben-test-2.0.3/"$CHANNEL"/"$FULLVERSION"/

