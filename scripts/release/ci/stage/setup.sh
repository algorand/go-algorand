#!/usr/bin/env bash
# shellcheck disable=2029

# Path(s) are relative to the root of the Jenkins workspace.

INSTANCE=$(cat scripts/release/tmp/instance)

#rm -rf pkg/* && mkdir -p pkg/"$FULLVERSION"
#aws s3 sync s3://ben-test-2.0.3/"$2"/"$1" pkg/
ssh -i ReleaseBuildInstanceKey.pem -A ubuntu@"$INSTANCE" mkdir node_pkg
scp -i ReleaseBuildInstanceKey.pem -o StrictHostKeyChecking=no -r pkg/*{.rpm*,.deb*} ubuntu@"$INSTANCE":~/node_pkg/

#aws s3 cp s3://algorand-devops-misc/tools/gnupg2.2.9_centos7_amd64.tar.bz2 .
#scp -i ReleaseBuildInstanceKey.pem -o StrictHostKeyChecking=no -r gnupg2.2.9_centos7_amd64.tar.bz2 ubuntu@"$INSTANCE":
#
#scp -i ReleaseBuildInstanceKey.pem -o StrictHostKeyChecking=no -r scripts/release/ci/setup.sh ubuntu@"$INSTANCE":
#ssh -i ReleaseBuildInstanceKey.pem -A ubuntu@"$INSTANCE" bash setup.sh "$1" "$2"

