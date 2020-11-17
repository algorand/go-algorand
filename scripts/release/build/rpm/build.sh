#!/usr/bin/env bash
# shellcheck disable=1090

echo
date "+build_release start BUILD CENTOS DOCKER stage %Y%m%d_%H%M%S"
echo

set -ex

export HOME=/root

. "${HOME}"/subhome/build_env

mkdir -p "${HOME}/go/src/github.com/algorand"
cd "${HOME}/go/src/github.com/algorand"
if ! git clone --single-branch --branch "${BRANCH}" https://github.com/algorand/go-algorand go-algorand
then
    echo There has been a problem cloning the "$BRANCH" branch.
    exit 1
fi
cd go-algorand
# Install go build version specified by get_golang_version.sh and build its own copy of go-algorand.
if ! GOLANG_VERSION=$(./scripts/check_golang_version.sh)
then
    echo "${GOLANG_VERSION}"
    exit 1
fi
cd "${HOME}"
if ! curl -O "https://dl.google.com/go/go${GOLANG_VERSION}.linux-amd64.tar.gz"
then
    echo Golang could not be installed!
    exit 1
fi
bash -c "cd /usr/local && tar zxf ${HOME}/go*.tar.gz"

GOPATH=$(/usr/local/go/bin/go env GOPATH)
export PATH=${HOME}/gpgbin:${GOPATH}/bin:/usr/local/go/bin:${PATH}
export GOPATH

REPO_DIR=/root/go/src/github.com/algorand/go-algorand

# Build!
"${REPO_DIR}"/scripts/configure_dev-deps.sh
cd "${REPO_DIR}"
make build

# Copy binaries to the host for use in the packaging stage.
cp "${GOPATH}"/bin/* /root/subhome/go/bin/

echo
date "+build_release end BUILD CENTOS DOCKER stage %Y%m%d_%H%M%S"
echo

