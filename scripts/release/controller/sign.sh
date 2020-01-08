#!/usr/bin/env bash
# shellcheck disable=1090,2129,2035
. "${HOME}/build_env"
set -ex

# Anchor our repo root reference location
#REPO_ROOT="$( cd "$(dirname "$0")" ; pwd -P )"/..
REPO_ROOT=/home/ubuntu/go/src/github.com/algorand/go-algorand/

# TODO
#git archive --prefix="algorand-${FULLVERSION}/" "${TAG}" | gzip > "${PKG_ROOT}/algorand_${CHANNEL}_source_${FULLVERSION}.tar.gz"

# create *.sig gpg signatures
cd "${PKG_ROOT}"
for i in *.tar.gz *.deb *.rpm
do
    gpg -u "${SIGNING_KEY_ADDR}" --detach-sign "${i}"
done
HASHFILE=hashes_${CHANNEL}_${OS}_${ARCH}_${FULLVERSION}
rm -f "${HASHFILE}"
touch "${HASHFILE}"

# For an explanation of the "-- *.tar.gz" below
# see https://github.com/koalaman/shellcheck/wiki/SC2035
md5sum *.tar.gz *.deb *.rpm >> "${HASHFILE}"
shasum -a 256 *.tar.gz *.deb *.rpm >> "${HASHFILE}"
shasum -a 512 *.tar.gz *.deb *.rpm >> "${HASHFILE}"

if [ -z "${SIGNING_KEY_ADDR}" ]
then
    echo "no signing key addr"
    SIGNING_KEY_ADDR=dev@algorand.com
fi

gpg -u "${SIGNING_KEY_ADDR}" --detach-sign "${HASHFILE}"
gpg -u "${SIGNING_KEY_ADDR}" --clearsign "${HASHFILE}"

cp -p "${REPO_ROOT}/installer/rpm/algorand.repo" "${HOME}/prodrepo/algorand.repo"

gpg --export -a dev@algorand.com > "${HOME}/docker_test_resources/key.pub"
gpg --export -a rpm@algorand.com > "${HOME}/docker_test_resources/rpm.pub"

date "+build_release done signing %Y%m%d_%H%M%S"

