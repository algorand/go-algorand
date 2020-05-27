#!/usr/bin/env bash
# shellcheck disable=1090,2129,2035

set -ex

echo
date "+build_release begin SIGN stage %Y%m%d_%H%M%S"
echo

. "${HOME}/build_env"

sg docker "docker run --rm --env-file ${HOME}/build_env_docker --mount type=bind,src=/run/user/1000/gnupg/S.gpg-agent,dst=/root/S.gpg-agent --mount type=bind,src=${HOME}/keys,dst=/root/keys --mount type=bind,src=${HOME},dst=/root/subhome algocentosbuild /root/subhome/go/src/github.com/algorand/go-algorand/scripts/release/build/rpm/sign.sh"

pushd "${REPO_ROOT}"
git archive --prefix="algorand-${FULLVERSION}/" "${BRANCH}" | gzip > "${PKG_ROOT}/algorand_${CHANNEL}_source_${FULLVERSION}.tar.gz"
popd

cd "${PKG_ROOT}" || exit
for i in *.tar.gz *.deb
do
    gpg -u "${SIGNING_KEY_ADDR}" --detach-sign "${i}"
done

for i in *.rpm
do
    gpg -u rpm@algorand.com --detach-sign "${i}"
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

echo
date "+build_release end SIGN stage %Y%m%d_%H%M%S"
echo

