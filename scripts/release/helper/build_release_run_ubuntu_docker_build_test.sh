#!/usr/bin/env bash
#
# This script exists to give a trap atexit context for killing the httpd so that we're not waiting on that

set -ex

(cd ${HOME}/dummyaptly/public && python3 ${GOPATH}/src/github.com/algorand/go-algorand/scripts/httpd.py --pid ${HOME}/phttpd.pid) &
trap ${GOPATH}/src/github.com/algorand/go-algorand/scripts/kill_httpd.sh 0

# Ubuntu 16 binaries are deprecated. Should still work to build from source for it.
sg docker "docker run --rm --env-file ${HOME}/build_env_docker --mount type=bind,src=${HOME}/docker_test_resources,dst=/root/stuff --mount type=bind,src=${HOME}/go,dst=/root/go --mount type=bind,src=/usr/local/go,dst=/usr/local/go ubuntu:16.04 bash ${HOME}/release/helper/build_release_ubuntu_test_docker.sh"

export DC_IP

sg docker "${GOPATH}/src/github.com/algorand/go-algorand/scripts/debian/start_docker_debian_test.sh ${HOME}/docker_test_resources"

