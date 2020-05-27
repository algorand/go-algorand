#!/usr/bin/env bash

set -ex

trap 'bash ./scripts/release/common/ec2/shutdown.sh' ERR

# Path(s) are relative to the root of the Jenkins workspace.

INSTANCE=$(cat scripts/release/common/ec2/tmp/instance)
BUILD_ENV=$(ssh -i ReleaseBuildInstanceKey.pem -A ubuntu@"$INSTANCE" cat build_env)
CHANNEL=$(sed -n 's/.*CHANNEL=\(.*\)/\1/p' <<< "$BUILD_ENV")
RELEASE=$(sed -n 's/.*FULLVERSION=\(.*\)/\1/p' <<< "$BUILD_ENV")

rm -rf ./*.deb ./*.rpm
python3 scripts/get_current_installers.py "s3://algorand-builds/channel/$CHANNEL/$RELEASE"

# Copy previous installers into ~.
scp -i ReleaseBuildInstanceKey.pem -o StrictHostKeyChecking=no ./*.deb ubuntu@"$INSTANCE":
ssh -i ReleaseBuildInstanceKey.pem -A ubuntu@"$INSTANCE" bash go/src/github.com/algorand/go-algorand/scripts/release/test/stage/test/task.sh

