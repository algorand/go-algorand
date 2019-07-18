#!/bin/bash
set -x
set -v
TEST_NAME=$1
TEST_DIR=$3
echo "start docker test: " $TEST_NAME
echo "test dir: " $TEST_DIR

#set TMPDIR for aptly to use
TMPDIR=$TEST_DIR

STATUS=0

# build the docker container algotest using the local Dockerfile
docker build -t algotest:latest .

# run the docker container
CONTAINER_ID=$(
docker run -d -v /sys/fs/cgroup:/sys/fs/cgroup:ro \
  --cap-add SYS_ADMIN \
  --mount type=bind,src=`(pwd)`,dst=/workdir \
  --mount type=bind,src=`(pwd)`/../cli/goal/expect,dst=/expectdir \
  -v type=bind,src=${TEST_DIR},dst=/testdir \
  algotest:latest \
  /sbin/init
)
echo "docker container id" ${CONTAINER_ID}

ls $TEST_DIR

#exec the test driver
docker exec -t ${CONTAINER_ID} /workdir/deb_setup.sh || STATUS=1

#destroy the docker container
docker kill ${CONTAINER_ID}

echo "start_docker completed with status: " $STATUS

exit $STATUS
