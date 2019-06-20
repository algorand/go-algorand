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
EOF
# strip leading 'export ' for docker --env-file
sed 's/^export //g' < ${HOME}/build_env > ${HOME}/build_env_docker

# Build!
scripts/configure_dev.sh

make ${GOPATH}/src/github.com/algorand/go-algorand/crypto/lib/libsodium.a

make build

scripts/build_packages.sh "${PLATFORM}"

date "+build_release done building ubuntu %Y%m%d_%H%M%S"

# Run RPM bulid in Centos7 Docker container
sg docker "docker build -t algocentosbuild - < scripts/centos-build.Dockerfile"

# cleanup our libsodium build
if [ -f ${GOPATH}/src/github.com/algorand/go-algorand/crypto/libsodium-fork/Makefile ]; then
    (cd ${GOPATH}/src/github.com/algorand/go-algorand/crypto/libsodium-fork && make distclean)
fi
rm -rf ${GOPATH}/src/github.com/algorand/go-algorand/crypto/lib

# do the RPM build
sg docker "docker run --env-file ${HOME}/build_env_docker --mount type=bind,src=${GOPATH}/src,dst=/root/go/src --mount type=bind,src=${HOME},dst=/root/subhome --mount type=bind,src=/usr/local/go,dst=/usr/local/go -a stdout -a stderr algocentosbuild /root/go/src/github.com/algorand/go-algorand/scripts/build_release_centos_docker.sh"

date "+build_release done building centos %Y%m%d_%H%M%S"

# NEXT: build_release_sign.sh

