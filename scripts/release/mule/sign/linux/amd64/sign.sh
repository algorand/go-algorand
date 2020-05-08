#!/usr/bin/env bash

set -ex

echo
date "+build_release begin SIGN stage %Y%m%d_%H%M%S"
echo

WORKDIR="$1"

if [ -z "$WORKDIR" ]
then
    echo "WORKDIR variable must be defined."
    exit 1
fi

OS_TYPE="$2"
ARCH="$3"
VERSION=${VERSION:-$4}
PKG_TYPE="$5"

BRANCH=${BRANCH:-$(git rev-parse --abbrev-ref HEAD)}
CHANNEL=${CHANNEL:-$("$WORKDIR/scripts/compute_branch_channel.sh" "$BRANCH")}
PKG_DIR="$WORKDIR/tmp/node_pkgs/$OS_TYPE/$ARCH"
SIGNING_KEY_ADDR=dev@algorand.com

# TODO
#if ! $USE_CACHE
#then
#    mule -f package-test.yaml "package-test-setup-$PKG_TYPE"
#fi

GPG_HOME_DIR=$(gpgconf --list-dirs | grep homedir | awk -F: '{ print $2 }')
chmod 400 "$GPG_HOME_DIR"

if [ "$PKG_TYPE" == "source" ]
then
    git archive --prefix="algorand-$FULLVERSION/" "$BRANCH" | gzip > "$PKG_DIR/algorand_${CHANNEL}_source_${VERSION}.tar.gz"
    PKG_TYPE="tar.gz"
elif [ "$PKG_TYPE" == "rpm" ]
then
    SIGNING_KEY_ADDR=rpm@algorand.com
fi

cd "$PKG_DIR"

for item in *"$VERSION"*."$PKG_TYPE"
do
    gpg -u "$SIGNING_KEY_ADDR" --detach-sign "$item"
done

HASHFILE="hashes_${CHANNEL}_${OS_TYPE}_${ARCH}_${VERSION}_${PKG_TYPE}"
rm -f "$HASHFILE"
touch "$HASHFILE"

{
    md5sum ./*"$VERSION"*."$PKG_TYPE" ;
    shasum -a 256 ./*"$VERSION"*."$PKG_TYPE" ;
    shasum -a 512 ./*"$VERSION"*."$PKG_TYPE" ;
} >> "$HASHFILE"

gpg -u "$SIGNING_KEY_ADDR" --detach-sign "$HASHFILE"
gpg -u "$SIGNING_KEY_ADDR" --clearsign "$HASHFILE"

echo
date "+build_release end SIGN stage %Y%m%d_%H%M%S"
echo

