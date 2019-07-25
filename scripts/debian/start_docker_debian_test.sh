#!/bin/bash
set -x
set -v
echo "Starting start_docker.sh"
TEST_NAME="DebianTest"
TEST_DIR=/tmp/debian-installer-test
echo "start docker test: " $TEST_NAME
echo "test dir: " $TEST_DIR

TMPDIR=$TEST_DIR
KEY_DIR=$1
echo "KEY_DIR: $KEY_DIR"
echo "DC_IP: $DC_IP"
STATUS=0

mkdir -p  ${TEST_DIR}

# run the docker container
docker \
  run --rm --env-file ${HOME}/build_env_docker \
  --mount type=bind,src=${GOPATH}/src/github.com/algorand/go-algorand/scripts/debian/,dst=/workdir \
  --mount type=bind,src=${GOPATH}/src/github.com/algorand/go-algorand/test/e2e-go/cli/goal/expect,dst=/expectdir \
  --mount type=bind,src=${GOPATH}/src/github.com/algorand/go-algorand/test/testdata,dst=/testdata \
  --mount type=bind,src=${KEY_DIR},dst=/stuff \
  -v type=bind,src=${TEST_DIR},dst=/testdir \
  debian:stable \
  bash /workdir/deb_test.sh

echo "start_docker completed with status: " $STATUS

exit $STATUS
