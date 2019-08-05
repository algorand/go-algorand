#!/bin/bash
. ${HOME}/build_env
set -e
set -x

# Anchor our repo root reference location
REPO_ROOT="$( cd "$(dirname "$0")" ; pwd -P )"/..

cd ${REPO_ROOT}

# Tag Source
TAG=${BRANCH}-${FULLVERSION}
echo "TAG=${TAG}" >> ${HOME}/build_env
if [ ! -z "${SIGNING_KEY_ADDR}" ]; then
    git tag -s -u "${SIGNING_KEY_ADDR}" ${TAG} -m "Genesis Timestamp: $(cat ./genesistimestamp.dat)"
else
    git tag -s ${TAG} -m "Genesis Timestamp: $(cat ./genesistimestamp.dat)"
fi

git archive --prefix=algorand-${FULLVERSION}/ "${TAG}" | gzip > ${PKG_ROOT}/algorand_${CHANNEL}_source_${FULLVERSION}.tar.gz

# create *.sig gpg signatures
cd ${PKG_ROOT}
for i in *.tar.gz *.deb *.rpm; do
    gpg -u "${SIGNING_KEY_ADDR}" --detach-sign "${i}"
done
HASHFILE=hashes_${CHANNEL}_${OS}_${ARCH}_${FULLVERSION}
rm -f "${HASHFILE}"
touch "${HASHFILE}"
md5sum *.tar.gz *.deb *.rpm >> "${HASHFILE}"
shasum -a 256 *.tar.gz *.deb *.rpm >> "${HASHFILE}"
shasum -a 512 *.tar.gz *.deb *.rpm >> "${HASHFILE}"
gpg -u "${SIGNING_KEY_ADDR}" --detach-sign "${HASHFILE}"
gpg -u "${SIGNING_KEY_ADDR}" --clearsign "${HASHFILE}"

date "+build_release done signing %Y%m%d_%H%M%S"

# NEXT: build_release_upload.sh
