#!/usr/bin/env bash
# shellcheck disable=1090

echo
date "+build_release begin PACKAGE DEB stage %Y%m%d_%H%M%S"
echo

. "${HOME}"/build_env

set -ex

export BUILD_DEB=1
export NO_BUILD=1
export GOPATH="${HOME}"/go
export PATH="${GOPATH}":/usr/local/go/bin:"${PATH}"
REPO_ROOT="${HOME}"/go/src/github.com/algorand/go-algorand
pushd "${REPO_ROOT}"
./scripts/build_packages.sh "${PLATFORM}"
popd

# build docker release package
cd "${REPO_ROOT}"/docker/release
sg docker "./build_algod_docker.sh ${HOME}/node_pkg/node_${CHANNEL}_${OS}-${ARCH}_${FULLVERSION}.tar.gz"

echo
date "+build_release end PACKAGE DEB stage %Y%m%d_%H%M%S"
echo

