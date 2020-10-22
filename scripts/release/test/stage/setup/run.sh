#!/usr/bin/env bash
# shellcheck disable=2029

set -ex

trap 'bash ./scripts/release/common/ec2/shutdown.sh' ERR

# Path(s) are relative to the root of the Jenkins workspace.
BRANCH=$(./scripts/release/util/check_remote.sh "$1")
INSTANCE=$(cat scripts/release/common/ec2/tmp/instance)

aws s3 cp s3://algorand-devops-misc/tools/gnupg2.2.9_centos7_amd64.tar.bz2 .
scp -i ReleaseBuildInstanceKey.pem -o StrictHostKeyChecking=no -r gnupg2.2.9_centos7_amd64.tar.bz2 ubuntu@"$INSTANCE":

scp -i ReleaseBuildInstanceKey.pem -o StrictHostKeyChecking=no -r scripts/release/common/setup.sh ubuntu@"$INSTANCE":
ssh -i ReleaseBuildInstanceKey.pem -A ubuntu@"$INSTANCE" bash setup.sh "$BRANCH"

BUILD_ENV=$(ssh -i ReleaseBuildInstanceKey.pem -A ubuntu@"$INSTANCE" cat build_env)
CHANNEL=$(sed -n 's/.*CHANNEL=\(.*\)/\1/p' <<< "$BUILD_ENV")
RELEASE=$(sed -n 's/.*FULLVERSION=\(.*\)/\1/p' <<< "$BUILD_ENV")

rm -rf pkg/* && mkdir -p pkg/"$RELEASE"

aws s3 sync "s3://algorand-staging/releases/$CHANNEL/$RELEASE/" pkg/ --exclude "*" --include "*.deb" --include "*.rpm"

# Upload the packages and their signatures.
scp -i ReleaseBuildInstanceKey.pem -o StrictHostKeyChecking=no -r pkg/* ubuntu@"$INSTANCE":~/node_pkg/

