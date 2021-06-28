#!/usr/bin/env bash
# shellcheck disable=1090

set -ex

echo
date "+build_release begin BUILD stage %Y%m%d_%H%M%S"
echo

. "${HOME}/build_env"

export GOPATH=${HOME}/go
export PATH=${HOME}/gpgbin:${GOPATH}/bin:/usr/local/go/bin:${PATH}

cd "${REPO_ROOT}"
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

# Run RPM build in Centos7 Docker container
sg docker "docker build -t algocentosbuild - < $HOME/go/src/github.com/algorand/go-algorand/scripts/release/common/docker/centos.Dockerfile"
sg docker "docker run --rm --env-file ${HOME}/build_env_docker --mount type=bind,src=${HOME},dst=/root/subhome algocentosbuild /root/subhome/go/src/github.com/algorand/go-algorand/scripts/release/build/rpm/build.sh"

# Run RPM build in Centos8 Docker container
sg docker "docker build -t algocentos8build - < $HOME/go/src/github.com/algorand/go-algorand/scripts/release/common/docker/centos8.Dockerfile"
sg docker "docker run --rm --env-file ${HOME}/build_env_docker --mount type=bind,src=${HOME},dst=/root/subhome algocentos8build /root/subhome/go/src/github.com/algorand/go-algorand/scripts/release/build/rpm/build.sh"

echo
date "+build_release end BUILD stage %Y%m%d_%H%M%S"
echo

