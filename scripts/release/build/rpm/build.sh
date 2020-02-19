#!/usr/bin/env bash
# shellcheck disable=1090

echo
date "+build_release start BUILD CENTOS DOCKER stage %Y%m%d_%H%M%S"
echo

set -ex

export HOME=/root

. "${HOME}"/subhome/build_env

GIT_REPO_PATH=https://github.com/algorand/go-algorand
mkdir -p "${HOME}/go/src/github.com/algorand"
cd "${HOME}/go/src/github.com/algorand" && git clone --single-branch --branch "${BRANCH}" "${GIT_REPO_PATH}" go-algorand

# Get golang 1.12 and build its own copy of go-algorand.
cd "${HOME}"
python3 "${HOME}/go/src/github.com/algorand/go-algorand/scripts/get_latest_go.py" --version-prefix=1.12
bash -c "cd /usr/local && tar zxf ${HOME}/go*.tar.gz"

GOPATH=$(/usr/local/go/bin/go env GOPATH)
export PATH=${HOME}/gpgbin:${GOPATH}/bin:/usr/local/go/bin:${PATH}
export GOPATH

REPO_DIR=/root/go/src/github.com/algorand/go-algorand

# Build!
"${REPO_DIR}"/scripts/configure_dev-deps.sh
cd "${REPO_DIR}"
make crypto/lib/libsodium.a
make build

# Copy binaries to the host for use in the packaging stage.
cp "${GOPATH}"/bin/* /root/subhome/go/bin/

echo
date "+build_release end BUILD CENTOS DOCKER stage %Y%m%d_%H%M%S"
echo

