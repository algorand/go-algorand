#!/usr/bin/env bash
# shellcheck disable=1090

set -ex

. "${HOME}"/build_env

# Run RPM build in Centos 7 & 8 Docker container
sg docker "docker build -t algocentosbuild - < ${HOME}/go/src/github.com/algorand/go-algorand/scripts/release/common/docker/centos.Dockerfile"

sg docker "docker run --rm --env-file ${HOME}/build_env_docker --mount type=bind,src=/run/user/1000/gnupg/S.gpg-agent,dst=/root/S.gpg-agent --mount type=bind,src=${HOME}/prodrepo,dst=/root/prodrepo --mount type=bind,src=${HOME}/keys,dst=/root/keys --mount type=bind,src=${HOME},dst=/root/subhome algocentosbuild /root/subhome/go/src/github.com/algorand/go-algorand/scripts/release/prod/rpm/snapshot.sh"

