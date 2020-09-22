#!/usr/bin/env bash

set -ex

trap 'bash ./scripts/release/common/ec2/shutdown.sh' ERR

# Path(s) are relative to the root of the Jenkins workspace.
ssh -i ReleaseBuildInstanceKey.pem -A ubuntu@"$(cat scripts/release/common/ec2/tmp/instance)" bash go/src/github.com/algorand/go-algorand/scripts/release/build/stage/build/task.sh

