#!/usr/bin/env bash
# shellcheck disable=1091,2012,2166
#
# This script needs to be run in a terminal with a human watching to
# be prompted for GPG key password at a couple points.
#
# Externally settable env vars:
# S3_PREFIX= where to upload build artifacts (no trailing /)
# RSTAMP= `scripts/reverse_hex_timestamp`
# AWS_ACCESS_KEY_ID=
# AWS_SECRET_ACCESS_KEY=

date "+build_release start %Y%m%d_%H%M%S"

set -ex

# Anchor our repo root reference location
# /home/ubuntu/..
# /home/ubuntu/go/src/github.com/algorand/go-algorand/
#REPO_ROOT="$( cd "$(dirname "$0")" ; pwd -P )"/..
REPO_ROOT=/home/ubuntu/go/src/github.com/algorand/go-algorand/
if [ -f ${REPO_ROOT}/crypto/libsodium-fork/Makefile ]; then
    (cd ${REPO_ROOT}/crypto/libsodium-fork && make distclean)
fi
rm -rf ${REPO_ROOT}/crypto/lib

cd ${REPO_ROOT}
export RELEASE_GENESIS_PROCESS=true
PLATFORM=$(./scripts/osarchtype.sh)
PLATFORM_SPLIT=(${PLATFORM//\// })
OS=${PLATFORM_SPLIT[0]}
ARCH=${PLATFORM_SPLIT[1]}
BRANCH=$(./scripts/compute_branch.sh)
export BRANCH
CHANNEL=$(./scripts/compute_branch_channel.sh "${BRANCH}")
export CHANNEL
DEFAULTNETWORK=$(./scripts/compute_branch_network.sh)
export DEFAULTNETWORK
export PKG_ROOT=${HOME}/node_pkg
export VARIATIONS="base"
# tell underlying 'build' scripts we already built
export NO_BUILD=true

RSTAMP=$(scripts/reverse_hex_timestamp)
echo RSTAMP="${RSTAMP}" > "${HOME}/rstamp"

# What's my default IP address?
# get the datacenter IP address for this EC2 host.
# this might equivalently be gotten from `netstat -rn` and `ifconfig -a`
DC_IP=$(curl --silent http://169.254.169.254/latest/meta-data/local-ipv4)
if [ -z "${DC_IP}" ]; then
    echo "ERROR: need DC_IP to be set to your local (but not localhost) IP"
    exit 1
fi

# Update version file for this build
if [ ! -z "${BUILD_NUMBER}" ]; then
    echo "using externally set BUILD_NUMBER=${BUILD_NUMBER} without incrementing"
else
    if [ -e buildnumber.dat ]; then
	BUILD_NUMBER=$(cat ./buildnumber.dat)
	BUILD_NUMBER=$(( BUILD_NUMBER + 1 ))
    else
	BUILD_NUMBER=0
    fi
    echo ${BUILD_NUMBER} > ./buildnumber.dat
    git add -A
    git commit -m "Build ${BUILD_NUMBER}"
fi
FULLVERSION=$(./scripts/compute_build_number.sh -f)
export FULLVERSION

# a bash user might `source build_env` to manually continue a broken build
cat <<EOF>"${HOME}"/build_env
export RELEASE_GENESIS_PROCESS=${RELEASE_GENESIS_PROCESS}
PLATFORM=${PLATFORM}
OS=${OS}
ARCH=${ARCH}
export BRANCH=${BRANCH}
export CHANNEL=${CHANNEL}
export DEFAULTNETWORK=${DEFAULTNETWORK}
export PKG_ROOT=${PKG_ROOT}
export VARIATIONS=${VARIATIONS}
RSTAMP=${RSTAMP}
BUILD_NUMBER=${BUILD_NUMBER}
export FULLVERSION=${FULLVERSION}
DC_IP=${DC_IP}
EOF
# strip leading 'export ' for docker --env-file
sed 's/^export //g' < "${HOME}"/build_env > "${HOME}"/build_env_docker

export GOPATH=${HOME}/go
export PATH=${HOME}/gpgbin:${GOPATH}/bin:/usr/local/go/bin:${PATH}

# Build!
scripts/configure_dev.sh

make crypto/lib/libsodium.a

make build

export BUILD_DEB=1
scripts/build_packages.sh "${PLATFORM}"

# build docker release package
cd ${REPO_ROOT}/docker/release
sg docker "./build_algod_docker.sh ${HOME}/node_pkg/node_${CHANNEL}_${OS}-${ARCH}_${FULLVERSION}.tar.gz"
cd ${REPO_ROOT}/scripts

# Test .deb installer
#. get_centos_gpg.sh

#export GNUPGHOME=${HOME}/tkey
#gpgconf --kill gpg-agent
#rm -rf "${GNUPGHOME}"
#mkdir -p "${GNUPGHOME}"
#chmod 700 "${GNUPGHOME}"
#cat >"${HOME}"/tkey/keygenscript<<EOF
#Key-Type: default
#Subkey-Type: default
#Name-Real: Algorand developers
#Name-Email: dev@algorand.com
#Expire-Date: 0
#Passphrase: foogorand
#%transient-key
#EOF
#cat >"${HOME}"/tkey/rpmkeygenscript<<EOF
#Key-Type: default
#Subkey-Type: default
#Name-Real: Algorand RPM
#Name-Email: rpm@algorand.com
#Expire-Date: 0
#Passphrase: foogorand
#%transient-key
#EOF
#cat <<EOF>"${GNUPGHOME}"/gpg-agent.conf
#extra-socket "${GNUPGHOME}"/S.gpg-agent.extra
## enable unattended daemon mode
#allow-preset-passphrase
## cache password 30 days
#default-cache-ttl 2592000
#max-cache-ttl 2592000
#EOF

#gpg --gen-key --batch "${HOME}"/tkey/keygenscript
#gpg --gen-key --batch "${HOME}"/tkey/rpmkeygenscript
#gpg --export -a dev@algorand.com > "${HOME}/docker_test_resources/key.pub"
#gpg --export -a rpm@algorand.com > "${HOME}/docker_test_resources/rpm.pub"

#gpgconf --kill gpg-agent
#gpgconf --launch gpg-agent

#gpgp=$(ls /usr/lib/gnupg{2,,1}/gpg-preset-passphrase | head -1)
#KEYGRIP=$(gpg -K --with-keygrip --textmode dev@algorand.com | grep Keygrip | head -1 | awk '{ print $3 }')
#echo foogorand | ${gpgp} --verbose --preset "${KEYGRIP}"
#KEYGRIP=$(gpg -K --with-keygrip --textmode rpm@algorand.com | grep Keygrip | head -1 | awk '{ print $3 }')
#echo foogorand | ${gpgp} --verbose --preset "${KEYGRIP}"

# copy previous installers into ~/docker_test_resources
mkdir -p "${HOME}/docker_test_resources"
cd "${HOME}/docker_test_resources"
if [ "${TEST_UPGRADE}" == "no" -o -z "${S3_PREFIX}" ]; then
    echo "upgrade test disabled"
else
    python3 ${REPO_ROOT}/scripts/get_current_installers.py "${S3_PREFIX}/${CHANNEL}"
fi

echo "TEST_UPGRADE=${TEST_UPGRADE}" >> "${HOME}/build_env_docker"

#rm -rf "${HOME}/dummyaptly"
mkdir -p "${HOME}/dummyaptly"
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
  "gpgDisableSign": true,
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
aptly -config="${HOME}"/dummyaptly.conf repo create -distribution=stable -component=main algodummy
aptly -config="${HOME}"/dummyaptly.conf repo add algodummy "${HOME}"/node_pkg/*.deb
SNAPSHOT=algodummy-$(date +%Y%m%d_%H%M%S)
aptly -config="${HOME}"/dummyaptly.conf snapshot create "${SNAPSHOT}" from repo algodummy
aptly -config="${HOME}"/dummyaptly.conf publish snapshot -origin=Algorand -label=Algorand "${SNAPSHOT}"

${REPO_ROOT}/scripts/release/helper/build_release_run_ubuntu_docker_build_test.sh

date "+build_release done building ubuntu %Y%m%d_%H%M%S"

# Run RPM build in Centos7 Docker container
sg docker "docker build -t algocentosbuild - < ${REPO_ROOT}/scripts/centos-build.Dockerfile"

# cleanup our libsodium build
if [ -f ${REPO_ROOT}/crypto/libsodium-fork/Makefile ]; then
    (cd ${REPO_ROOT}/crypto/libsodium-fork && make distclean)
fi
rm -rf ${REPO_ROOT}/crypto/lib

# do the RPM build, sign and validate it

#sudo rm -rf "${HOME}/dummyrepo"
#mkdir -p "${HOME}/dummyrepo"
#
#cat <<EOF>"${HOME}"/dummyrepo/algodummy.repo
#[algodummy]
#name=Algorand
#baseurl=http://${DC_IP}:8111/
#enabled=1
#gpgcheck=1
#gpgkey=https://releases.algorand.com/rpm/rpm_algorand.pub
#EOF
#(cd "${HOME}/dummyrepo" && python3 "${REPO_ROOT}/scripts/httpd.py" --pid "${HOME}"/phttpd.pid) &
#trap ${REPO_ROOT}/scripts/kill_httpd.sh 0

#sg docker "docker run --rm --env-file ${HOME}/build_env_docker --mount type=bind,src=${GNUPGHOME}/S.gpg-agent.extra,dst=/S.gpg-agent --mount type=bind,src=${HOME}/dummyrepo,dst=/dummyrepo --mount type=bind,src=${HOME}/docker_test_resources,dst=/stuff --mount type=bind,src=${GOPATH}/src,dst=/root/go/src --mount type=bind,src=${HOME},dst=/root/subhome --mount type=bind,src=/usr/local/go,dst=/usr/local/go algocentosbuild /root/go/src/github.com/algorand/go-algorand/scripts/release/helper/build_release_centos_docker.sh"

date "+build_release done building centos %Y%m%d_%H%M%S"

# NEXT: build_release_sign.sh
