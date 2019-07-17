#!/bin/bash
set -x
set -v 
echo "start_docker"

STATUS=0

# build the docker container algotest
docker build -t algotest:latest .

# run the docker container
docker run -d -v /sys/fs/cgroup:/sys/fs/cgroup:ro \
  --cap-add SYS_ADMIN \
  --mount type=bind,src=`(pwd)`,dst=/workdir \
  --mount type=bind,src=`(pwd)`/../cli/goal/expect,dst=/expectdir \
  algotest:latest \
  /sbin/init \
  /workdir/deb_setup.sh


CONTAINER_ID=`(docker ps | grep algotest:latest | awk '{ print $1 }')`
docker exec -t ${CONTAINER_ID} /workdir/deb_setup.sh && STATUS=0  || STATUS=1

docker kill ${CONTAINER_ID}


echo "start_docker completed successfully"

exit $STATUS

