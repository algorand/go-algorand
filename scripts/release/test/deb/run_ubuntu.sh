#!/usr/bin/env bash

set -ex

cat <<EOF>"${HOME}"/dummyaptly.conf
{
  "rootDir": "${HOME}/dummyaptly",
  "downloadConcurrency": 4,
  "downloadSpeedLimit": 0,
  "architectures": [],
  "dependencyFollowSuggests": false,
  "dependencyFollowRecommends": false,
  "dependencyFollowAllVariants": false,
  "dependencyFollowSource": false,
  "dependencyVerboseResolve": false,
  "gpgDisableSign": false,
  "gpgDisableVerify": false,
  "gpgProvider": "gpg",
  "downloadSourcePackages": false,
  "skipLegacyPool": true,
  "ppaDistributorID": "ubuntu",
  "ppaCodename": "",
  "skipContentsPublishing": false,
  "FileSystemPublishEndpoints": {},
  "S3PublishEndpoints": {},
  "SwiftPublishEndpoints": {}
}
EOF

# Creates ~/dummyaptly/db
"$HOME"/go/bin/aptly -config="${HOME}"/dummyaptly.conf repo create -distribution=stable -component=main algodummy
# Creates ~/dummyaptly/pool
"$HOME"/go/bin/aptly -config="${HOME}"/dummyaptly.conf repo add algodummy "${HOME}"/node_pkg/*.deb
SNAPSHOT=algodummy-$(date +%Y%m%d_%H%M%S)
"$HOME"/go/bin/aptly -config="${HOME}"/dummyaptly.conf snapshot create "${SNAPSHOT}" from repo algodummy
# Creates ~/dummyaptly/public
"$HOME"/go/bin/aptly -config="${HOME}"/dummyaptly.conf publish snapshot -origin=Algorand -label=Algorand "${SNAPSHOT}"

(cd "${HOME}"/dummyaptly/public && python3 "${HOME}"/go/src/github.com/algorand/go-algorand/scripts/httpd.py --pid "${HOME}"/phttpd.pid) &
trap "${HOME}"/go/src/github.com/algorand/go-algorand/scripts/kill_httpd.sh 0

sg docker "docker run --rm --env-file ${HOME}/build_env_docker --mount type=bind,src=${HOME}/keys,dst=/root/keys --mount type=bind,src=${HOME},dst=/root/subhome --mount type=bind,src=${HOME}/go,dst=/root/go --mount type=bind,src=/usr/local/go,dst=/usr/local/go ubuntu:16.04 bash /root/subhome/go/src/github.com/algorand/go-algorand/scripts/release/test/deb/test_algorand.sh"

export DC_IP

echo "Starting start_docker_debian_test.sh"
GOPATH=${HOME}/go
TEST_NAME="DebianTest"
echo "start docker test: " $TEST_NAME

echo "DC_IP: $DC_IP"
STATUS=0

# run the docker container
sg docker "docker run --rm --env-file ${HOME}/build_env_docker \
  --mount type=bind,src=${GOPATH}/src/github.com/algorand/go-algorand/scripts/release/test,dst=/workdir \
  --mount type=bind,src=${GOPATH}/src/github.com/algorand/go-algorand/test/e2e-go/cli/goal/expect,dst=/expectdir \
  --mount type=bind,src=${GOPATH}/src/github.com/algorand/go-algorand/test/testdata,dst=/testdata \
  --mount type=bind,src=${HOME}/keys,dst=/root/keys \
  debian:stable bash /workdir/deb/test_apt-get.sh"

STATUS=$?

echo "start_docker_debian_test completed with status: " $STATUS

exit $STATUS

