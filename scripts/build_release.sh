#!/bin/bash
#
# This script needs to be run in a terminal with a human watching to
# be prompted for GPG key password at a couple points.
#
# Externally settable env vars:
# S3_PREFIX= where to upload build artifacts (no trailing /)
# S3_PREFIX_BUILDLOG= where upload build log (no trailing /)
# AWS_EFS_MOUNT= NFS to mount for `aptly` persistent state and scratch storage
# SIGNING_KEY_ADDR= dev@algorand.com or similar for GPG key
# RSTAMP= `scripts/reverse_hex_timestamp`
# AWS_ACCESS_KEY_ID=
# AWS_SECRET_ACCESS_KEY=

date "+build_release start %Y%m%d_%H%M%S"

set -e
set -x

# a previous docker centos build can leave junk owned by root. chown and clean
sudo chown -R ${USER} ${GOPATH}
if [ -f ${GOPATH}/src/github.com/algorand/go-algorand/crypto/libsodium-fork/Makefile ]; then
    (cd ${GOPATH}/src/github.com/algorand/go-algorand/crypto/libsodium-fork && make distclean)
fi
rm -rf ${GOPATH}/src/github.com/algorand/go-algorand/crypto/lib


cd ${GOPATH}/src/github.com/algorand/go-algorand
export RELEASE_GENESIS_PROCESS=true
export TRANSITION_TELEMETRY_BUILDS=true
PLATFORM=$(./scripts/osarchtype.sh)
PLATFORM_SPLIT=(${PLATFORM//\// })
OS=${PLATFORM_SPLIT[0]}
ARCH=${PLATFORM_SPLIT[1]}
export BRANCH=rel/stable
export CHANNEL=$(./scripts/compute_branch_channel.sh ${BRANCH})
export DEFAULTNETWORK=$(./scripts/compute_branch_network.sh)
export PKG_ROOT=${HOME}/node_pkg
export VARIATIONS="base"
# tell underlying 'build' scripts we already built
export NO_BUILD=true
if [ -z "${RSTAMP}" ]; then
    RSTAMP=$(scripts/reverse_hex_timestamp)
    echo RSTAMP=${RSTAMP} > "${HOME}/rstamp"
fi
# What's my default IP address?
# get the datacenter IP address for this EC2 host.
# this might equivalently be gotten from `netstat -rn` and `ifconfig -a`
if [ -z "${DC_IP}" ]; then
    DC_IP=$(curl --silent http://169.254.169.254/latest/meta-data/local-ipv4)
fi
if [ -z "${DC_IP}" ]; then
    echo "ERROR: need DC_IP to be set to your local (but not localhost) IP"
    exit 1
fi

# Update version file for this build
BUILD_NUMBER=
if [ -e buildnumber.dat ]; then
    BUILD_NUMBER=$(cat ./buildnumber.dat)
    BUILD_NUMBER=$((${BUILD_NUMBER} + 1))
else
    BUILD_NUMBER=0
fi
echo ${BUILD_NUMBER} > ./buildnumber.dat
git add -A
git commit -m "Build ${BUILD_NUMBER}"
export FULLVERSION=$(./scripts/compute_build_number.sh -f)

# a bash user might `source build_env` to manually continue a broken build
cat <<EOF>${HOME}/build_env
export RELEASE_GENESIS_PROCESS=${RELEASE_GENESIS_PROCESS}
export TRANSITION_TELEMETRY_BUILDS=${TRANSITION_TELEMETRY_BUILDS}
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
sed 's/^export //g' < ${HOME}/build_env > ${HOME}/build_env_docker

# Build!
scripts/configure_dev.sh

make crypto/lib/libsodium.a

make build

export BUILD_DEB=1
scripts/build_packages.sh "${PLATFORM}"


# Test .deb installer

mkdir -p ${HOME}/docker_test_resources
if [ ! -f "${HOME}/docker_test_resources/gnupg2.2.9_centos7_amd64.tar.bz2" ]; then
    aws s3 cp s3://algorand-devops-misc/tools/gnupg2.2.9_centos7_amd64.tar.bz2 ${HOME}/docker_test_resources
fi
cp -p "${HOME}/key.gpg" "${HOME}/docker_test_resources/key.pub"

# copy previous installers into ~/docker_test_resources
cd "${HOME}/docker_test_resources"
if [ "${TEST_UPGRADE}" == "no" ]; then
    echo "upgrade test disabled"
else
    python3 ${GOPATH}/src/github.com/algorand/go-algorand/scripts/get_current_installers.py "${S3_PREFIX}/${CHANNEL}"
fi

echo "TEST_UPGRADE=${TEST_UPGRADE}" >> ${HOME}/build_env_docker

rm -rf ${HOME}/dummyaptly
mkdir -p ${HOME}/dummyaptly
cat <<EOF>${HOME}/dummyaptly.conf
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
aptly -config=${HOME}/dummyaptly.conf repo create -distribution=stable -component=main algodummy
aptly -config=${HOME}/dummyaptly.conf repo add algodummy ${HOME}/node_pkg/*.deb
SNAPSHOT=algodummy-$(date +%Y%m%d_%H%M%S)
aptly -config=${HOME}/dummyaptly.conf snapshot create ${SNAPSHOT} from repo algodummy
aptly -config=${HOME}/dummyaptly.conf publish snapshot -origin=Algorand -label=Algorand ${SNAPSHOT}

(cd ${HOME}/dummyaptly/public && python3 ${GOPATH}/src/github.com/algorand/go-algorand/scripts/httpd.py --pid ${HOME}/phttpd.pid) &


sg docker "docker run --rm --env-file ${HOME}/build_env_docker --mount type=bind,src=${HOME}/docker_test_resources,dst=/stuff --mount type=bind,src=${GOPATH}/src,dst=/root/go/src --mount type=bind,src=/usr/local/go,dst=/usr/local/go ubuntu:16.04 bash /root/go/src/github.com/algorand/go-algorand/scripts/build_release_ubuntu_test_docker.sh"
sg docker "docker run --rm --env-file ${HOME}/build_env_docker --mount type=bind,src=${HOME}/docker_test_resources,dst=/stuff --mount type=bind,src=${GOPATH}/src,dst=/root/go/src --mount type=bind,src=/usr/local/go,dst=/usr/local/go ubuntu:18.04 bash /root/go/src/github.com/algorand/go-algorand/scripts/build_release_ubuntu_test_docker.sh"

kill $(cat ${HOME}/phttpd.pid)

date "+build_release done building ubuntu %Y%m%d_%H%M%S"

# Run RPM bulid in Centos7 Docker container
sg docker "docker build -t algocentosbuild - < ${GOPATH}/src/github.com/algorand/go-algorand/scripts/centos-build.Dockerfile"

# cleanup our libsodium build
if [ -f ${GOPATH}/src/github.com/algorand/go-algorand/crypto/libsodium-fork/Makefile ]; then
    (cd ${GOPATH}/src/github.com/algorand/go-algorand/crypto/libsodium-fork && make distclean)
fi
rm -rf ${GOPATH}/src/github.com/algorand/go-algorand/crypto/lib

# do the RPM build, sign and validate it

sudo rm -rf ${HOME}/dummyrepo
mkdir -p ${HOME}/dummyrepo

cat <<EOF>${HOME}/dummyrepo/algodummy.repo
[algodummy]
name=Algorand
baseurl=http://${DC_IP}:8111/
enabled=1
gpgcheck=1
gpgkey=https://releases.algorand.com/rpm/rpm_algorand.pub
EOF
(cd ${HOME}/dummyrepo && python3 ${GOPATH}/src/github.com/algorand/go-algorand/scripts/httpd.py --pid ${HOME}/phttpd.pid) &

sg docker "docker run --rm --env-file ${HOME}/build_env_docker --mount type=bind,src=${HOME}/.gnupg/S.gpg-agent,dst=/S.gpg-agent --mount type=bind,src=${HOME}/dummyrepo,dst=/dummyrepo --mount type=bind,src=${HOME}/docker_test_resources,dst=/stuff --mount type=bind,src=${GOPATH}/src,dst=/root/go/src --mount type=bind,src=${HOME},dst=/root/subhome --mount type=bind,src=/usr/local/go,dst=/usr/local/go algocentosbuild /root/go/src/github.com/algorand/go-algorand/scripts/build_release_centos_docker.sh"

kill $(cat ${HOME}/phttpd.pid)

date "+build_release done building centos %Y%m%d_%H%M%S"

# NEXT: build_release_sign.sh

