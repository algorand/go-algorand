#!/bin/bash

set -ex

echo "Building RPM package"

REPO_DIR=$(pwd)
FULLVERSION=${VERSION:-$(./scripts/compute_build_number.sh -f)}
BRANCH=${BRANCH:-$(git rev-parse --abbrev-ref HEAD)}
CHANNEL=${CHANNEL:-$(./scripts/compute_branch_channel.sh "$BRANCH")}
# TODO: Should there be a default network?
DEFAULTNETWORK=devnet
DEFAULT_RELEASE_NETWORK=$(./scripts/compute_branch_release_network.sh "$DEFAULTNETWORK")

find tmp/node_pkgs -name "*${CHANNEL}*linux*${FULLVERSION}*.tar.gz" | cut -d '/' -f3-4 | sort --unique | while read OS_ARCH; do
    OS_TYPE=$(echo "${OS_ARCH}" | cut -d '/' -f1)
    ARCH=$(echo "${OS_ARCH}" | cut -d '/' -f2)
    ALGO_BIN="$REPO_DIR/tmp/node_pkgs/$OS_TYPE/$ARCH/$CHANNEL/$OS_TYPE-$ARCH/bin"
    # A make target in Makefile.mule may pass the name as an argument.
    ALGORAND_PACKAGE_NAME=${1:-$(./scripts/compute_package_name.sh "$CHANNEL")}

    if [[ "$ALGORAND_PACKAGE_NAME" =~ devtools ]]; then
        REQUIRED_ALGORAND_PACKAGE=$(./scripts/compute_package_name.sh "$CHANNEL")
    fi

    # The following need to be exported for use in ./go-algorand/installer/rpm/$ALGORAND_PACKAGE_NAME/$ALGORAND_PACKAGE_NAME.spec.
    export DEFAULT_NETWORK
    export DEFAULT_RELEASE_NETWORK
    export REPO_DIR
    export ALGO_BIN

    RPMTMP=$(mktemp -d 2>/dev/null || mktemp -d -t "rpmtmp")
    trap 'rm -rf $RPMTMP' 0

    TEMPDIR=$(mktemp -d)
    if [[ "$ALGORAND_PACKAGE_NAME" =~ devtools ]]; then
        INSTALLER_DIR="algorand-devtools"
    else
        INSTALLER_DIR=algorand
    fi
    trap 'rm -rf $TEMPDIR' 0
    < "./installer/rpm/$INSTALLER_DIR/$INSTALLER_DIR.spec" \
        sed -e "s,@PKG_NAME@,$ALGORAND_PACKAGE_NAME," \
            -e "s,@VER@,$FULLVERSION," \
            -e "s,@ARCH@,$ARCH_TYPE," \
            -e "s,@REQUIRED_ALGORAND_PKG@,$REQUIRED_ALGORAND_PACKAGE," \
        > "$TEMPDIR/$ALGORAND_PACKAGE_NAME.spec"

    rpmbuild --buildroot "$HOME/foo" --define "_rpmdir $RPMTMP" --define "RELEASE_GENESIS_PROCESS x$RELEASE_GENESIS_PROCESS" --define "LICENSE_FILE ./COPYING" -bb "$TEMPDIR/$ALGORAND_PACKAGE_NAME.spec"

    cp -p "$RPMTMP"/*/*.rpm "./tmp/node_pkgs/$OS_TYPE/$ARCH_TYPE"
done
