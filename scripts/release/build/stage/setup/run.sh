#!/usr/bin/env bash
# shellcheck disable=2029

# Path(s) are relative to the root of the Jenkins workspace.

INSTANCE=$(cat scripts/release/tmp/instance)

#ssh -i ReleaseBuildInstanceKey.pem -A ubuntu@"$INSTANCE" mkdir docker_test_resources
aws s3 cp s3://algorand-devops-misc/tools/gnupg2.2.9_centos7_amd64.tar.bz2 .
scp -i ReleaseBuildInstanceKey.pem -o StrictHostKeyChecking=no -r scripts/release/build/stage/setup/task.sh gnupg2.2.9_centos7_amd64.tar.bz2 ubuntu@"$INSTANCE":
ssh -i ReleaseBuildInstanceKey.pem -A ubuntu@"$INSTANCE" bash task.sh "$1" "$2"

