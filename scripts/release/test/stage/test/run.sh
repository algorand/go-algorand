#!/usr/bin/env bash

# Path(s) are relative to the root of the Jenkins workspace.

INSTANCE=$(cat scripts/release/common/ec2/tmp/instance)

rm -rf ./*.deb ./*.rpm
python3 scripts/get_current_installers.py "$1/$2"

# Copy previous installers into ~.
scp -i ReleaseBuildInstanceKey.pem -o StrictHostKeyChecking=no ./*.deb ubuntu@"$INSTANCE":
ssh -i ReleaseBuildInstanceKey.pem -A ubuntu@"$INSTANCE" bash go/src/github.com/algorand/go-algorand/scripts/release/test/stage/test/task.sh

