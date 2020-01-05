#!/usr/bin/env bash
# shellcheck disable=2164,2166

REPO_ROOT=/home/ubuntu/go/src/github.com/algorand/go-algorand/

# copy previous installers into ~/docker_test_resources
cd "${HOME}/docker_test_resources"
if [ "${TEST_UPGRADE}" == "no" -o -z "${S3_PREFIX}" ]; then
    echo "upgrade test disabled"
else
    python3 "${REPO_ROOT}/scripts/get_current_installers.py" "${S3_PREFIX}/${CHANNEL}"
fi

echo "TEST_UPGRADE=${TEST_UPGRADE}" >> "${HOME}/build_env_docker"

cat <<EOF>"${HOME}"/dummyaptly.conf
{
  "rootDir": "${HOME}/dummyaptly",
  "downloadConcurrency": 4,
  "downloadSpeedLimit": 0,
  "architectures": [],
  "dependencyFollowSuggests": false,
  "dependencyFollowRecommends": false,
  "dependencyFollowAllVariants": false,
  "dependencyFollowSource": false,
  "dependencyVerboseResolve": false,
  "gpgDisableSign": false,
  "gpgDisableVerify": false,
  "gpgProvider": "gpg",
  "downloadSourcePackages": false,
  "skipLegacyPool": true,
  "ppaDistributorID": "ubuntu",
  "ppaCodename": "",
  "skipContentsPublishing": false,
  "FileSystemPublishEndpoints": {},
  "S3PublishEndpoints": {},
  "SwiftPublishEndpoints": {}
}
EOF
"$HOME"/go/bin/aptly -config="${HOME}"/dummyaptly.conf repo create -distribution=stable -component=main algodummy
"$HOME"/go/bin/aptly -config="${HOME}"/dummyaptly.conf repo add algodummy "${HOME}"/node_pkg/*.deb
SNAPSHOT=algodummy-$(date +%Y%m%d_%H%M%S)
"$HOME"/go/bin/aptly -config="${HOME}"/dummyaptly.conf snapshot create "${SNAPSHOT}" from repo algodummy
"$HOME"/go/bin/aptly -config="${HOME}"/dummyaptly.conf publish snapshot -origin=Algorand -label=Algorand "${SNAPSHOT}"

#/home/ubuntu/release/helper/build_release_run_ubuntu_docker_build_test.sh

date "+build_release done building ubuntu %Y%m%d_%H%M%S"

# Run RPM build in Centos7 Docker container
sg docker "docker build -t algocentosbuild - < ${REPO_ROOT}/scripts/release/helper/centos-build.Dockerfile"

# cleanup our libsodium build
#if [ -f "${REPO_ROOT}/crypto/libsodium-fork/Makefile" ]; then
#    (cd "${REPO_ROOT}/crypto/libsodium-fork" && make distclean)
#fi
#rm -rf "${REPO_ROOT}/crypto/lib"

# do the RPM build, sign and validate it

cat <<EOF>"${HOME}"/dummyrepo/algodummy.repo
[algodummy]
name=Algorand
baseurl=http://${DC_IP}:8111/
enabled=1
gpgcheck=1
gpgkey=https://releases.algorand.com/rpm/rpm_algorand.pub
EOF
#(cd "${HOME}/dummyrepo" && python3 "${REPO_ROOT}/scripts/httpd.py" --pid "${HOME}"/phttpd.pid) &
## https://github.com/koalaman/shellcheck/wiki/SC2064
#trap '${REPO_ROOT}/scripts/kill_httpd.sh' 0

sg docker "docker run --rm --env-file ${HOME}/build_env_docker --mount type=bind,src=/run/user/1000/gnupg/S.gpg-agent,dst=/S.gpg-agent --mount type=bind,src=${HOME}/dummyrepo,dst=/dummyrepo --mount type=bind,src=${HOME}/docker_test_resources,dst=/root/stuff --mount type=bind,src=${HOME}/go,dst=/root/go --mount type=bind,src=${HOME},dst=/root/subhome --mount type=bind,src=/usr/local/go,dst=/usr/local/go algocentosbuild /root/go/src/github.com/algorand/go-algorand/scripts/release/helper/build_release_centos_docker.sh"

date "+build_release done building centos %Y%m%d_%H%M%S"

# NEXT: sign.sh

