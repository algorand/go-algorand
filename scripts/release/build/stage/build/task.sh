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
export NO_BUILD=true

# Update version file for this build
if [ ! -z "${BUILD_NUMBER}" ]; then
    echo "using externally set BUILD_NUMBER=${BUILD_NUMBER} without incrementing"
else
    if [ -e "${REPO_ROOT}"/buildnumber.dat ]
    then
        BUILD_NUMBER=$(cat "${REPO_ROOT}"/buildnumber.dat)
    else
        BUILD_NUMBER=0
    fi

    echo ${BUILD_NUMBER} > "${REPO_ROOT}"/buildnumber.dat
fi
FULLVERSION=$(PATH=${PATH} "${REPO_ROOT}"/scripts/compute_build_number.sh -f)
echo "${FULLVERSION}" > "${REPO_ROOT}"/fullversion.dat
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

# Run RPM build in Centos7 Docker container
sg docker "docker build -t algocentosbuild - < $HOME/go/src/github.com/algorand/go-algorand/scripts/release/centos-build.Dockerfile"

sg docker "docker run --rm --env-file ${HOME}/build_env_docker --mount type=bind,src=${HOME},dst=/root/subhome algocentosbuild /root/subhome/go/src/github.com/algorand/go-algorand/scripts/release/build/rpm/build.sh"

echo
date "+build_release end BUILD stage %Y%m%d_%H%M%S"
echo

