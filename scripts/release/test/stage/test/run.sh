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

INSTANCE=$(cat scripts/release/common/ec2/tmp/instance)

rm -rf ./*.deb ./*.rpm
#python3 scripts/get_current_installers.py "$1/$CHANNEL"
python3 scripts/get_current_installers.py "algorand-builds/$CHANNEL"

# Copy previous installers into ~.
scp -i ReleaseBuildInstanceKey.pem -o StrictHostKeyChecking=no ./*.deb ubuntu@"$INSTANCE":
#ssh -i ReleaseBuildInstanceKey.pem -A ubuntu@"$INSTANCE" bash go/src/github.com/algorand/go-algorand/scripts/release/test/stage/test/task.sh
ssh -i ReleaseBuildInstanceKey.pem -A ubuntu@"$INSTANCE" bash ben-branch/scripts/release/test/stage/test/task.sh

