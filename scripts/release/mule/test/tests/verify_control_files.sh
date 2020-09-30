#!/usr/bin/env bash
# shellcheck disable=2035

set -ex

echo "[$0] Testing control files"

# We're looking for a line that looks like the following:
#
#       Pre-Depends: algorand (>= 2.1.6)
#

DIR=/root/pkg

mkdir -p $DIR
cp "./tmp/node_pkgs/$OS_TYPE/$ARCH_TYPE"/algorand-devtools*"$VERSION"*.deb $DIR
cd $DIR
ar xv *"$VERSION"*.deb
tar xf control.tar.xz

if ! grep -F "Pre-Depends: algorand (>= $VERSION)" control
then
    echo "[$0] The dependency for algorand version $VERSION is incorrect."
    exit 1
fi

echo "[$0] The dependency for algorand version $VERSION is correct."
exit 0

