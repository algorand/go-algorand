#!/usr/bin/env bash
# shellcheck disable=2029

set -ex

trap 'bash ./scripts/release/common/ec2/shutdown.sh' ERR

# Path(s) are relative to the root of the Jenkins workspace.
BRANCH=$(./scripts/release/util/check_remote.sh "$1")
INSTANCE=$(cat scripts/release/common/ec2/tmp/instance)
#BUCKET="$1"

BUILD_ENV=$(ssh -i ReleaseBuildInstanceKey.pem -o -A ubuntu@"$INSTANCE" cat build_env)
CHANNEL=$(sed -n 's/.*CHANNEL=\(.*\)/\1/p' <<< "$BUILD_ENV")
FULLVERSION=$(sed -n 's/.*FULLVERSION=\(.*\)/\1/p' <<< "$BUILD_ENV")

rm -rf pkg
mkdir -p pkg/"$FULLVERSION"

aws s3 sync s3://"$BUCKET"/"$CHANNEL"/"$FULLVERSION" pkg/ --exclude "*" --include "*.deb" --include "*.rpm"
ssh -i ReleaseBuildInstanceKey.pem -A ubuntu@"$INSTANCE" mkdir node_pkg
scp -i ReleaseBuildInstanceKey.pem -o StrictHostKeyChecking=no -r pkg/* ubuntu@"$INSTANCE":~/node_pkg/

aws s3 cp s3://algorand-devops-misc/tools/gnupg2.2.9_centos7_amd64.tar.bz2 .
scp -i ReleaseBuildInstanceKey.pem -o StrictHostKeyChecking=no -r gnupg2.2.9_centos7_amd64.tar.bz2 ubuntu@"$INSTANCE":

#scp -i ReleaseBuildInstanceKey.pem -o StrictHostKeyChecking=no -r scripts/release/prod/stage/setup/task.sh ubuntu@"$INSTANCE":
scp -i ReleaseBuildInstanceKey.pem -o StrictHostKeyChecking=no -r scripts/release/common/setup.sh ubuntu@"$INSTANCE":
ssh -i ReleaseBuildInstanceKey.pem -A ubuntu@"$INSTANCE" bash setup.sh "$BRANCH" "$CHANNEL" "$FULLVERSION"

