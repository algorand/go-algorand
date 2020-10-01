#!/usr/bin/env bash
# shellcheck disable=2035

set -ex

echo "[$0] Testing control files"

RPMTMP=$(mktemp -d)

if [ "$PKG_TYPE" = deb ]
then
    #
    # We're looking for a line that looks like the following:
    #
    #       Pre-Depends: algorand (>= 2.1.6)
    #

    cp "./tmp/node_pkgs/$OS_TYPE/$ARCH_TYPE"/algorand-devtools*"$VERSION"*.deb "$RPMTMP"
    ar xv "$RPMTMP"/*"$VERSION"*.deb
    tar xf "$RPMTMP"/control.tar.xz

    if ! grep -F "Pre-Depends: algorand (>= $VERSION)" "$RPMTMP"/control
    then
        echo "[$0] The dependency for algorand version $VERSION is incorrect."
        exit 1
    fi

    echo "[$0] The dependency for algorand version $VERSION is correct."
else
    cp "./tmp/node_pkgs/$OS_TYPE/$ARCH_TYPE"/algorand-devtools*"$VERSION"*"$ARCH_BIT".rpm "$RPMTMP"
#    yumdownloader --source algorand
fi

