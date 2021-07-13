#!/usr/bin/env bash
# shellcheck disable=1090

echo
date "+build_release begin PACKAGE RPM stage %Y%m%d_%H%M%S"
echo

. "${HOME}/build_env"
set -ex

sg docker "docker run --rm --env-file ${HOME}/build_env_docker --mount type=bind,src=${HOME},dst=/root/subhome algocentosbuild /root/subhome/go/src/github.com/algorand/go-algorand/scripts/release/build/rpm/package.sh"
sg docker "docker run --rm --env-file ${HOME}/build_env_docker --mount type=bind,src=${HOME},dst=/root/subhome algocentos8build /root/subhome/go/src/github.com/algorand/go-algorand/scripts/release/build/rpm/package.sh"

echo
date "+build_release end PACKAGE RPM stage %Y%m%d_%H%M%S"
echo

