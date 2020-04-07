#!/usr/bin/env bash
# shellcheck disable=1090

set -ex

. "${HOME}"/build_env

echo
date "+build_release begin TEST stage %Y%m%d_%H%M%S"
echo

sg docker "docker build -t algocentosbuild - < ${HOME}/go/src/github.com/algorand/go-algorand/scripts/release/common/centos-build.Dockerfile"

cat <<EOF>"${HOME}"/dummyrepo/algodummy.repo
[algodummy]
name=Algorand
baseurl=http://${DC_IP}:8111/
enabled=1
gpgcheck=1
gpgkey=https://releases.algorand.com/rpm/rpm_algorand.pub
EOF

cd "${HOME}"/dummyrepo && python3 "${HOME}"/go/src/github.com/algorand/go-algorand/scripts/httpd.py --pid "${HOME}"/phttpd.pid &
trap "${HOME}"/go/src/github.com/algorand/go-algorand/scripts/kill_httpd.sh 0

sg docker "docker run --rm --env-file ${HOME}/build_env_docker --mount type=bind,src=/run/user/1000/gnupg/S.gpg-agent,dst=/root/S.gpg-agent --mount type=bind,src=${HOME}/dummyrepo,dst=/root/dummyrepo --mount type=bind,src=${HOME}/keys,dst=/root/keys --mount type=bind,src=${HOME},dst=/root/subhome algocentosbuild /root/subhome/go/src/github.com/algorand/go-algorand/scripts/release/test/rpm/test_algorand.sh"

echo
date "+build_release end TEST stage %Y%m%d_%H%M%S"
echo

