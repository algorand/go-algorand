#!/usr/bin/env bash
#
# This script exists to give a trap atexit context for killing the httpd so that we're not waiting on that

set -ex

(cd "${HOME}"/dummyaptly/public && python3 "${HOME}"/go/src/github.com/algorand/go-algorand/scripts/httpd.py --pid "${HOME}"/phttpd.pid) &
trap "${HOME}"/go/src/github.com/algorand/go-algorand/scripts/kill_httpd.sh 0

sg docker "docker run --rm --env-file ${HOME}/build_env_docker --mount type=bind,src=${HOME}/docker_test_resources,dst=/root/stuff --mount type=bind,src=${HOME}/go,dst=/root/go --mount type=bind,src=/usr/local/go,dst=/usr/local/go ubuntu:16.04 bash /root/go/src/github.com/algorand/go-algorand/scripts/release/helper/docker_ubuntu_test.sh"

export DC_IP

sg docker "${HOME}/go/src/github.com/algorand/go-algorand/scripts/release/helper/docker_debian_test.sh ${HOME}/docker_test_resources"

