#!/usr/bin/env bash
# shellcheck disable=1090

echo
date "+build_release begin PACKAGE RPM stage %Y%m%d_%H%M%S"
echo

. "${HOME}/build_env"
set -x

cat <<EOF>"${HOME}"/dummyrepo/algodummy.repo
[algodummy]
name=Algorand
baseurl=http://${DC_IP}:8111/
enabled=1
gpgcheck=1
gpgkey=https://releases.algorand.com/rpm/rpm_algorand.pub
EOF

sg docker "docker run --rm --env-file ${HOME}/build_env_docker --mount type=bind,src=/run/user/1000/gnupg/S.gpg-agent,dst=/root/S.gpg-agent --mount type=bind,src=${HOME}/prodrepo,dst=/dummyrepo --mount type=bind,src=${HOME}/keys,dst=/root/keys --mount type=bind,src=${HOME},dst=/root/subhome algocentosbuild /root/subhome/ben-branch/scripts/release/ci/rpm/package.sh"

echo
date "+build_release end PACKAGE RPM stage %Y%m%d_%H%M%S"
echo

