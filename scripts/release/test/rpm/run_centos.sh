#!/usr/bin/env bash
# shellcheck disable=2012

set -x

echo
date "+build_release begin TEST stage %Y%m%d_%H%M%S"
echo

# Run RPM build in Centos7 Docker container
sg docker "docker build -t algocentosbuild - < ${HOME}/ben-branch/scripts/release/rpm/centos-build.Dockerfile"

cat <<EOF>"${HOME}"/dummyrepo/algodummy.repo
[algodummy]
name=Algorand
baseurl=http://${DC_IP}:8111/
enabled=1
gpgcheck=1
gpgkey=https://releases.algorand.com/rpm/rpm_algorand.pub
EOF

sg docker "docker run --rm --env-file ${HOME}/build_env --mount type=bind,src=/run/user/1000/gnupg/S.gpg-agent,dst=/root/S.gpg-agent --mount type=bind,src=${HOME}/dummyrepo,dst=/root/dummyrepo --mount type=bind,src=${HOME}/keys,dst=/root/keys --mount type=bind,src=${HOME},dst=/root/subhome algocentosbuild /root/subhome/ben-branch/scripts/release/test/rpm/test_algorand.sh"

echo
date "+build_release end TEST stage %Y%m%d_%H%M%S"
echo

