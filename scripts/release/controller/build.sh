#!/usr/bin/env bash

echo
date "+build_release begin BUILD stage %Y%m%d_%H%M%S"
echo

set -ex

export GOPATH=${HOME}/go
export PATH=${HOME}/gpgbin:${GOPATH}/bin:/usr/local/go/bin:${PATH}

# Anchor our repo root reference location
REPO_ROOT="${HOME}"/go/src/github.com/algorand/go-algorand/

cd "${REPO_ROOT}"
export RELEASE_GENESIS_PROCESS=true
export HASH="$1"
export CHANNEL="$2"
PLATFORM=$("${REPO_ROOT}"/scripts/osarchtype.sh)
PLATFORM_SPLIT=(${PLATFORM//\// })
OS=${PLATFORM_SPLIT[0]}
ARCH=${PLATFORM_SPLIT[1]}
DEFAULTNETWORK=$(PATH=${PATH} "${REPO_ROOT}"/scripts/compute_branch_network.sh)
export DEFAULTNETWORK
export PKG_ROOT=${HOME}/node_pkg
export VARIATIONS="base"
# tell underlying 'build' scripts we already built

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
FULLVERSION=$(PATH=${PATH} "${REPO_ROOT}"/scripts/compute_build_number.sh -f)
export FULLVERSION

# a bash user might `source build_env` to manually continue a broken build
cat <<EOF>>"${HOME}"/build_env
export RELEASE_GENESIS_PROCESS=${RELEASE_GENESIS_PROCESS}
PLATFORM=${PLATFORM}
OS=${OS}
ARCH=${ARCH}
export HASH=${HASH}
export CHANNEL=${CHANNEL}
export DEFAULTNETWORK=${DEFAULTNETWORK}
export PKG_ROOT=${PKG_ROOT}
export VARIATIONS=${VARIATIONS}
BUILD_NUMBER=${BUILD_NUMBER}
export FULLVERSION=${FULLVERSION}
DC_IP=${DC_IP}
REPO_ROOT=${REPO_ROOT}
EOF

# strip leading 'export ' for docker --env-file
sed 's/^export //g' < "${HOME}"/build_env > "${HOME}"/build_env_docker

# Build!
scripts/configure_dev.sh
make crypto/lib/libsodium.a
make build

export BUILD_DEB=1
export NO_BUILD=true

"${REPO_ROOT}"/scripts/build_packages.sh "${PLATFORM}"

# build docker release package
cd "${REPO_ROOT}"/docker/release
sg docker "./build_algod_docker.sh ${HOME}/node_pkg/node_${CHANNEL}_${OS}-${ARCH}_${FULLVERSION}.tar.gz"
cd "${REPO_ROOT}"/scripts

echo
date "+build_release end BUILD stage %Y%m%d_%H%M%S"
echo

