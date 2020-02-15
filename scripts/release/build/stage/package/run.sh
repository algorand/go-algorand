#!/usr/bin/env bash
# shellcheck disable=2029

set -ex

# Path(s) are relative to the root of the Jenkins workspace.
#ssh -i ReleaseBuildInstanceKey.pem -A ubuntu@"$(cat scripts/release/common/ec2/tmp/instance)" bash go/src/github.com/algorand/go-algorand/scripts/release/build/stage/package/task.sh
ssh -i ReleaseBuildInstanceKey.pem -A ubuntu@"$(cat scripts/release/common/ec2/tmp/instance)" bash ben-branch/scripts/release/build/stage/package/task.sh

