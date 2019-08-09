#!/bin/bash
#
# This script exists to give a trap atexit context for killing the httpd so that we're not waiting on that

set -e
set -x

(cd ${HOME}/dummyaptly/public && python3 ${GOPATH}/src/github.com/algorand/go-algorand/scripts/httpd.py --pid ${HOME}/phttpd.pid) &
trap ${GOPATH}/src/github.com/algorand/go-algorand/scripts/kill_httpd.sh 0

sg docker "docker run --rm --env-file ${HOME}/build_env_docker --mount type=bind,src=${HOME}/docker_test_resources,dst=/stuff --mount type=bind,src=${GOPATH}/src,dst=/root/go/src --mount type=bind,src=/usr/local/go,dst=/usr/local/go ubuntu:16.04 bash /root/go/src/github.com/algorand/go-algorand/scripts/build_release_ubuntu_test_docker.sh"
sg docker "docker run --rm --env-file ${HOME}/build_env_docker --mount type=bind,src=${HOME}/docker_test_resources,dst=/stuff --mount type=bind,src=${GOPATH}/src,dst=/root/go/src --mount type=bind,src=/usr/local/go,dst=/usr/local/go ubuntu:18.04 bash /root/go/src/github.com/algorand/go-algorand/scripts/build_release_ubuntu_test_docker.sh"

export DC_IP

sg docker "${GOPATH}/src/github.com/algorand/go-algorand/scripts/debian/start_docker_debian_test.sh ${HOME}/docker_test_resources"
