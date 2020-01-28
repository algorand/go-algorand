#!/usr/bin/env bash
# shellcheck disable=1090,2129,2035

echo
date "+build_release begin SIGN stage %Y%m%d_%H%M%S"
echo

. "${HOME}/build_env"
set -x

# Run RPM build in Centos7 Docker container
#sg docker "docker build -t algocentosbuild - < ${REPO_ROOT}/scripts/release/test/centos-build.Dockerfile"
sg docker "docker build -t algocentosbuild - < $HOME/ben-branch/scripts/release/test/centos-build.Dockerfile"

cat <<EOF>"${HOME}"/dummyrepo/algodummy.repo
[algodummy]
name=Algorand
baseurl=http://${DC_IP}:8111/
enabled=1
gpgcheck=1
gpgkey=https://releases.algorand.com/rpm/rpm_algorand.pub
EOF

#sg docker "docker run --rm --env-file ${HOME}/build_env_docker --mount type=bind,src=${GPG_AGENT_SOCKET},dst=/S.gpg-agent --mount type=bind,src=${HOME}/prodrepo,dst=/dummyrepo --mount type=bind,src=${HOME}/docker_test_resources,dst=/root/stuff --mount type=bind,src=${HOME}/go/src,dst=/root/go/src --mount type=bind,src=${HOME},dst=/root/subhome --mount type=bind,src=/usr/local/go,dst=/usr/local/go algocentosbuild /root/go/src/github.com/algorand/go-algorand/scripts/release/test/sign_centos_docker.sh"
sg docker "docker run --rm --env-file ${HOME}/build_env_docker --mount type=bind,src=/run/user/1000/gnupg/S.gpg-agent,dst=/root/S.gpg-agent --mount type=bind,src=${HOME}/prodrepo,dst=/dummyrepo --mount type=bind,src=${HOME}/docker_test_resources,dst=/root/stuff --mount type=bind,src=${HOME},dst=/root/subhome algocentosbuild /root/subhome/ben-branch/scripts/release/test/sign_centos_docker.sh"

# Anchor our repo root reference location
REPO_ROOT="${HOME}"/go/src/github.com/algorand/go-algorand/

pushd "${REPO_ROOT}"
git archive --prefix="algorand-${FULLVERSION}/" "${HASH}" | gzip > "${PKG_ROOT}/algorand_${CHANNEL}_source_${FULLVERSION}.tar.gz"
popd

# create *.sig gpg signatures
cd "${PKG_ROOT}" || exit
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

#GPG_AGENT_SOCKET=$("${HOME}"/gpgbin/remote_gpg_socket)

echo
date "+build_release end SIGN stage %Y%m%d_%H%M%S"
echo

