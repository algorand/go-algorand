#!/bin/bash
# shellcheck disable=2086,2162

set -ex

echo "Building RPM package"

if [ -z "$CHANNEL" ] || [ -z "$NETWORK" ] || [ -z "$VERSION" ]; then
    echo "[$0] CHANNEL=$CHANNEL, NETWORK=$NETWORK or VERSION=$VERSION is missing."
    exit 1
fi

REPO_DIR=$(pwd)
DEFAULTNETWORK="$NETWORK"
DEFAULT_RELEASE_NETWORK=$(./scripts/compute_branch_release_network.sh "$DEFAULTNETWORK")
PACKAGE_NAME="$1"

find tmp/node_pkgs -name "*${CHANNEL}*linux*${VERSION}*.tar.gz" | cut -d '/' -f3-4 | sort --unique | while read OS_ARCH; do
    OS_TYPE=$(echo "${OS_ARCH}" | cut -d '/' -f1)
    ARCH_TYPE=$(echo "${OS_ARCH}" | cut -d '/' -f2)
    ARCH_UNAME=$(./scripts/release/common/cpu_name.sh ${ARCH_TYPE})
    ALGO_BIN="$REPO_DIR/tmp/node_pkgs/$OS_TYPE/$ARCH_TYPE/$CHANNEL/$OS_TYPE-$ARCH_TYPE/bin"
    # A make target in Makefile.mule may pass the name as an argument.
    ALGORAND_PACKAGE_NAME=$(./scripts/compute_package_name.sh "$CHANNEL" "$PACKAGE_NAME")

    if [[ "$ALGORAND_PACKAGE_NAME" =~ devtools ]]; then
        REQUIRED_ALGORAND_PACKAGE=$(./scripts/compute_package_name.sh "$CHANNEL")
    fi

    # The following need to be exported for use in ./go-algorand/installer/rpm/$ALGORAND_PACKAGE_NAME/$ALGORAND_PACKAGE_NAME.spec.
    export DEFAULTNETWORK
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
            -e "s,@VER@,$VERSION," \
            -e "s,@ARCH@,$ARCH_UNAME," \
            -e "s,@REQUIRED_ALGORAND_PKG@,$REQUIRED_ALGORAND_PACKAGE," \
        > "$TEMPDIR/$ALGORAND_PACKAGE_NAME.spec"

    rpmbuild --buildroot "$HOME/foo" --define "_rpmdir $RPMTMP" --define "RELEASE_GENESIS_PROCESS xtrue" --define "LICENSE_FILE ./COPYING" -bb "$TEMPDIR/$ALGORAND_PACKAGE_NAME.spec" --target $ARCH_UNAME

    cp -p "$RPMTMP"/*/*.rpm "./tmp/node_pkgs/$OS_TYPE/$ARCH_TYPE"
    echo "${RPMTMP}"
    echo "${TEMPDIR}"
done
