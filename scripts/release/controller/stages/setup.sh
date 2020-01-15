#!/usr/bin/env bash
# shellcheck disable=2029

# Path(s) are relative to the root of the Jenkins workspace.

INSTANCE=$(cat scripts/release/tmp/instance)

aws s3 cp s3://algorand-devops-misc/tools/gnupg2.2.9_centos7_amd64.tar.bz2 .
ssh -i ReleaseBuildInstanceKey.pem -A ubuntu@"$INSTANCE" mkdir docker_test_resources
scp -i ReleaseBuildInstanceKey.pem -o StrictHostKeyChecking=no -r gnupg2.2.9_centos7_amd64.tar.bz2 ubuntu@"$INSTANCE":~/docker_test_resources/
scp -i ReleaseBuildInstanceKey.pem -o StrictHostKeyChecking=no -r scripts/release/controller/setup.sh ubuntu@"$INSTANCE":~/setup.sh
ssh -i ReleaseBuildInstanceKey.pem -A ubuntu@"$INSTANCE" bash setup.sh "$1" "$2"

