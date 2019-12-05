#!/usr/bin/env bash
. ${HOME}/build_env
set -e
set -x

# Anchor our repo root reference location
REPO_ROOT="$( cd "$(dirname "$0")" ; pwd -P )"/..

cd ${REPO_ROOT}

# Tag Source
TAG=${BRANCH}-${FULLVERSION}
echo "TAG=${TAG}" >> ${HOME}/build_env
# creating a signed tag is now a manual process upstream of this build
# git tag -s -u "${SIGNING_KEY_ADDR}" ${TAG} -m "Genesis Timestamp: $(cat ./genesistimestamp.dat)"

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

sudo rm -rf ${HOME}/prodrepo
mkdir -p ${HOME}/prodrepo
cp -p ${REPO_ROOT}/installer/rpm/algorand.repo ${HOME}/prodrepo/algorand.repo

. ${REPO_ROOT}/scripts/get_centos_gpg.sh
gpg --export -a dev@algorand.com > "${HOME}/docker_test_resources/key.pub"
gpg --export -a rpm@algorand.com > "${HOME}/docker_test_resources/rpm.pub"

GPG_AGENT_SOCKET=$(${HOME}/gpgbin/remote_gpg_socket)

sg docker "docker run --rm --env-file ${HOME}/build_env_docker --mount type=bind,src=${GPG_AGENT_SOCKET},dst=/S.gpg-agent --mount type=bind,src=${HOME}/prodrepo,dst=/dummyrepo --mount type=bind,src=${HOME}/docker_test_resources,dst=/stuff --mount type=bind,src=${GOPATH}/src,dst=/root/go/src --mount type=bind,src=${HOME},dst=/root/subhome --mount type=bind,src=/usr/local/go,dst=/usr/local/go algocentosbuild /root/go/src/github.com/algorand/go-algorand/scripts/sign_centos_docker.sh"

date "+build_release done signing %Y%m%d_%H%M%S"

# NEXT: build_release_upload.sh
