#!/usr/bin/env bash
#
# This script exists to give a trap atexit context for killing the httpd so that we're not waiting on that

set -ex

(cd "${HOME}"/dummyaptly/public && python3 "${HOME}"/go/src/github.com/algorand/go-algorand/scripts/httpd.py --pid "${HOME}"/phttpd.pid) &
trap "${HOME}"/go/src/github.com/algorand/go-algorand/scripts/kill_httpd.sh 0

sg docker "docker run --rm --env-file ${HOME}/build_env --mount type=bind,src=${HOME}/keys,dst=/root/keys --mount type=bind,src=${HOME},dst=/root/subhome --mount type=bind,src=${HOME}/go,dst=/root/go --mount type=bind,src=/usr/local/go,dst=/usr/local/go ubuntu:16.04 bash /root/subhome/ben-branch/scripts/release/test/deb/test_algorand.sh"

export DC_IP

echo "Starting start_docker_debian_test.sh"
GOPATH=${HOME}/go
TEST_NAME="DebianTest"
echo "start docker test: " $TEST_NAME

KEY_DIR=$1
echo "KEY_DIR: $KEY_DIR"
echo "DC_IP: $DC_IP"
STATUS=0

# run the docker container
sg docker "docker run --rm --env-file ${HOME}/build_env \
  --mount type=bind,src=${HOME}/ben-branch/scripts/release/test,dst=/workdir \
  --mount type=bind,src=${GOPATH}/src/github.com/algorand/go-algorand/test/e2e-go/cli/goal/expect,dst=/expectdir \
  --mount type=bind,src=${GOPATH}/src/github.com/algorand/go-algorand/test/testdata,dst=/testdata \
  --mount type=bind,src=${HOME}/keys,dst=/root/keys \
  debian:stable bash /workdir/deb/test_apt-get.sh"

STATUS=$?

echo "start_docker_debian_test completed with status: " $STATUS

exit $STATUS
#sg docker "${HOME}/go/src/github.com/algorand/go-algorand/scripts/release/test/docker_debian_test.sh ${HOME}/keys"

