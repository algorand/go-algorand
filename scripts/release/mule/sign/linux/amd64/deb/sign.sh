#!/usr/bin/env bash

set -ex

echo
date "+build_release begin SIGN deb stage %Y%m%d_%H%M%S"
echo

OS_TYPE="$1"
ARCH="$2"
WORKDIR="$3"

if [ -z "$OS_TYPE" ] || [ -z "$ARCH" ] || [ -z "$WORKDIR" ]; then
    echo "OS=$OS, ARCH=$ARCH and WORKDIR=$WORKDIR variables must be defined."
    exit 1
fi

if [ -z "${SIGNING_KEY_ADDR}" ]; then
    echo "no signing key addr"
    SIGNING_KEY_ADDR=dev@algorand.com
fi

#REPO_DIR="$WORKDIR"
PKG_ROOT_DIR="./tmp/node_pkgs/$OS_TYPE/$ARCH"

#pushd "${REPO_DIR}"
#git archive --prefix="algorand-${FULLVERSION}/" "${BRANCH}" | gzip > "${PKG_ROOT_DIR}/algorand_${CHANNEL}_source_${FULLVERSION}.tar.gz"
#popd

cd "${PKG_ROOT_DIR}"
for i in *.tar.gz *.deb
do
    gpg -u "${SIGNING_KEY_ADDR}" --detach-sign "${i}"
done

HASHFILE="hashes_${CHANNEL}_${OS}_${ARCH}_${FULLVERSION}"
rm -f "${HASHFILE}"
touch "${HASHFILE}"

{
    md5sum ./*.tar.gz ./*.deb ;
    shasum -a 256 ./*.tar.gz ./*.deb ;
    shasum -a 512 ./*.tar.gz ./*.deb ;
} >> "${HASHFILE}"

gpg -u "${SIGNING_KEY_ADDR}" --detach-sign "${HASHFILE}"
gpg -u "${SIGNING_KEY_ADDR}" --clearsign "${HASHFILE}"

echo
date "+build_release end SIGN stage %Y%m%d_%H%M%S"
echo

