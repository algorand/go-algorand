#!/usr/bin/env bash
# shellcheck disable=1090,2064

echo
date "+build_release begin PACKAGE DEB stage %Y%m%d_%H%M%S"
echo

. "${HOME}"/build_env

set -ex

export NO_BUILD=1
export GOPATH="${HOME}"/go
export PATH="${GOPATH}":/usr/local/go/bin:"${PATH}"

pushd "${REPO_ROOT}"
./scripts/build_packages.sh "${PLATFORM}"

DEBTMP=$(mktemp -d 2>/dev/null || mktemp -d -t "debtmp")
trap "rm -rf ${DEBTMP}" 0

if ! ./scripts/build_deb.sh "${ARCH}" "${DEBTMP}" "${CHANNEL}"
then
    echo "Error building debian package for ${PLATFORM}.  Aborting..."
    exit 1
fi

BRANCH=$("./scripts/compute_branch.sh")
CHANNEL=$("./scripts/compute_branch_channel.sh" "$BRANCH")

cp -p "${DEBTMP}"/*.deb "${PKG_ROOT}/algorand_${CHANNEL}_${OS}-${ARCH}_${FULLVERSION}.deb"
popd

# build docker release package
cd "${REPO_ROOT}"/docker/release
sg docker "${REPO_ROOT}/scripts/release/build/build_algod_docker.sh ${HOME}/node_pkg/node_${CHANNEL}_${OS}-${ARCH}_${FULLVERSION}.tar.gz"

echo
date "+build_release end PACKAGE DEB stage %Y%m%d_%H%M%S"
echo

