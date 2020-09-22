#!/usr/bin/env bash
# shellcheck disable=2035

set -exo pipefail

echo
date "+build_release begin SIGN stage %Y%m%d_%H%M%S"
echo

PKG_TYPE="$1"
ARCH_BIT=$(uname -m)
ARCH_TYPE=$(./scripts/archtype.sh)
OS_TYPE=$(./scripts/ostype.sh)
VERSION=${VERSION:-$(./scripts/compute_build_number.sh -f)}
BRANCH=${BRANCH:-$(git rev-parse --abbrev-ref HEAD)}
CHANNEL=${CHANNEL:-$(./scripts/compute_branch_channel.sh "$BRANCH")}
PKG_DIR="./tmp/node_pkgs/$OS_TYPE/$ARCH_TYPE"
SIGNING_KEY_ADDR=dev@algorand.com

if ! $USE_CACHE
then
    export ARCH_BIT
    export ARCH_TYPE
    export CHANNEL
    export OS_TYPE
    export VERSION

    if [ "$PKG_TYPE" == "tar.gz" ]
    then
        mule -f package-sign.yaml package-sign-setup-tarball
    else
        mule -f package-sign.yaml "package-sign-setup-$PKG_TYPE"
    fi
fi

make_hashes () {
    # We need to futz a bit with "source" to make the hashes correct.
    local HASH_TYPE=${1:-$PKG_TYPE}
    local PACKAGE_TYPE=${2:-$PKG_TYPE}

    HASHFILE="hashes_${CHANNEL}_${OS_TYPE}_${ARCH_TYPE}_${VERSION}_${HASH_TYPE}"
    # Remove any previously-generated hashes.
    rm -f "$HASHFILE"*

    {
        md5sum *"$VERSION"*."$PACKAGE_TYPE" ;
        shasum -a 256 *"$VERSION"*."$PACKAGE_TYPE" ;
        shasum -a 512 *"$VERSION"*."$PACKAGE_TYPE" ;
    } >> "$HASHFILE"

    gpg -u "$SIGNING_KEY_ADDR" --detach-sign "$HASHFILE"
    gpg -u "$SIGNING_KEY_ADDR" --clearsign "$HASHFILE"
}

make_sigs () {
    local PACKAGE_TYPE=${1:-$PKG_TYPE}

    # Remove any previously-generated signatures.
    rm -f ./*"$VERSION"*."$PACKAGE_TYPE".sig

    for item in *"$VERSION"*."$1"
    do
        gpg -u "$SIGNING_KEY_ADDR" --detach-sign "$item"
    done
}

pushd "$PKG_DIR"

GPG_HOME_DIR=$(gpgconf --list-dirs | grep homedir | awk -F: '{ print $2 }')
chmod 400 "$GPG_HOME_DIR"

if [ "$PKG_TYPE" == "source" ]
then
    git archive --prefix="algorand-$FULLVERSION/" "$BRANCH" | gzip >| "$PKG_DIR/algorand_${CHANNEL}_source_${VERSION}.tar.gz"
    make_sigs tar.gz
    make_hashes source tar.gz
else
    if [ "$PKG_TYPE" == "rpm" ]
    then
        SIGNING_KEY_ADDR=rpm@algorand.com
    fi

    make_sigs "$PKG_TYPE"
    make_hashes
fi

popd

echo
date "+build_release end SIGN stage %Y%m%d_%H%M%S"
echo

