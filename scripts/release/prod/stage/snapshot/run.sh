#!/usr/bin/env bash
# shellcheck disable=2029

# Path(s) are relative to the root of the Jenkins workspace.
INSTANCE=$(cat scripts/release/tmp/instance)

ssh -i ReleaseBuildInstanceKey.pem -A ubuntu@"$INSTANCE" bash ben-branch/scripts/release/prod/stage/snapshot/task.sh

