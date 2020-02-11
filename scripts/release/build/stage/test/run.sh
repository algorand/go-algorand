#!/usr/bin/env bash

# Path(s) are relative to the root of the Jenkins workspace.
INSTANCE=$(cat scripts/release/common/ec2/tmp/instance)

rm -rf ./*.deb ./*.rpm
python3 scripts/get_current_installers.py "$1/$2"

# Copy previous installers into ~/docker_test_resources.
scp -i ReleaseBuildInstanceKey.pem -o StrictHostKeyChecking=no ./*.deb ubuntu@"$INSTANCE":~/docker_test_resources/
ssh -i ReleaseBuildInstanceKey.pem -A ubuntu@"$INSTANCE" bash go/src/github.com/algorand/go-algorand/scripts/release/build/stage/test/task.sh

