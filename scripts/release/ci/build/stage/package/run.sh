#!/usr/bin/env bash
# shellcheck disable=2029

# Path(s) are relative to the root of the Jenkins workspace.

#ssh -i ReleaseBuildInstanceKey.pem -A ubuntu@"$(cat scripts/release/tmp/instance)" bash ben-branch/scripts/release/deb/package.sh "$1" "$2"
#ssh -i ReleaseBuildInstanceKey.pem -A ubuntu@"$(cat scripts/release/tmp/instance)" bash ben-branch/scripts/release/rpm/docker.sh "$1" "$2"

ssh -i ReleaseBuildInstanceKey.pem -A ubuntu@"$(cat scripts/release/tmp/instance)" bash ben-branch/scripts/release/ci/build/stage/package/task.sh "$1" "$2"

