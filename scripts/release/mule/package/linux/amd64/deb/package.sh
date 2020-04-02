#!/usr/bin/env bash

set -ex

echo
date "+build_release begin PACKAGE DEB stage %Y%m%d_%H%M%S"
echo

export BUILD_DEB=1
export NO_BUILD=1
export REPO_DIR=/projects/go-algorand
export GOPATH="$REPO_DIR/go"
export PATH="$GOPATH:/usr/local/go/bin:$PATH"
# TODO: Don't hardcode this path!
# Will change to something like:
# "$REPO_DIR/tmp/node_pkgs/$OS_TYPE/$ARCH/pkg"
export PKG_ROOT="$REPO_DIR/tmp/node_pkgs/linux/amd64/deb"
export VARIATIONS=linux/amd64
"$REPO_DIR/scripts/build_packages.sh" "$VARIATIONS"

#sg docker ""${REPO_ROOT}"/docker/release/build_algod_docker.sh ${HOME}/node_pkg/node_${CHANNEL}_${OS}-${ARCH}_${FULLVERSION}.tar.gz"

echo
date "+build_release end PACKAGE DEB stage %Y%m%d_%H%M%S"
echo

