#!/usr/bin/env bash

set -ex

echo "Building RPM package"

cd "$(dirname "$0")"/..

REPO_DIR="$HOME/subhome/go/src/github.com/algorand/go-algorand"
export REPO_DIR
DEFAULT_RELEASE_NETWORK=$("$REPO_DIR/scripts/compute_branch_release_network.sh" "$DEFAULTNETWORK")
export DEFAULT_RELEASE_NETWORK
DEFAULTNETWORK=devnet
export DEFAULT_NETWORK
ALGO_BIN="$HOME/subhome/go/bin"
export ALGO_BIN

BRANCH=$("$REPO_DIR/scripts/compute_branch.sh")
CHANNEL=$("$REPO_DIR/scripts/compute_branch_channel.sh" "$BRANCH")
ALGORAND_PACKAGE_NAME=$("$REPO_DIR/scripts/compute_package_name.sh" "${CHANNEL:-stable}")
DEVTOOLS_PACKAGE_NAME=$("$REPO_DIR/scripts/compute_package_name.sh" "${CHANNEL:-stable}" algorand-devtools)

PKG_NAMES=("$ALGORAND_PACKAGE_NAME" "$DEVTOOLS_PACKAGE_NAME")
for pkg_name in "${PKG_NAMES[@]}"; do
    RPMTMP=$(mktemp -d 2>/dev/null || mktemp -d -t "rpmtmp")
    trap 'rm -rf $RPMTMP' 0

    TEMPDIR=$(mktemp -d)
    trap 'rm -rf $TEMPDIR' 0

    mkdir "$TEMPDIR/$pkg_name"

    if [[ "$pkg_name" =~ devtools ]]; then
        INSTALLER_DIR="algorand-devtools"
    else
        INSTALLER_DIR=algorand
    fi

    echo "Building rpm package $pkg_name ($CHANNEL)"

    < "$REPO_DIR/installer/rpm/$INSTALLER_DIR/$INSTALLER_DIR.spec" \
        sed -e "s,@PKG_NAME@,$pkg_name," \
            -e "s,@VER@,$FULLVERSION," \
            -e "s,@REQUIRED_ALGORAND_PKG@,$ALGORAND_PACKAGE_NAME," \
        > "$TEMPDIR/$pkg_name/$pkg_name.spec"

    rpmbuild --define "_rpmdir $RPMTMP" --define "RELEASE_GENESIS_PROCESS x${RELEASE_GENESIS_PROCESS}" --define "LICENSE_FILE $REPO_DIR/COPYING" -bb "$TEMPDIR/$pkg_name/$pkg_name.spec"

    mkdir -p /root/subhome/node_pkg
    cp -p "$RPMTMP"/*/*.rpm /root/subhome/node_pkg
done

