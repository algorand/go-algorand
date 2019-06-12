#!/bin/bash
#
# This script needs to be run in a terminal with a human watching to
# be prompted for GPG key password at a couple points.
#
# Externally settable env vars:
# S3_PREFIX= where to upload build artifacts
# AWS_EFS_MOUNT= NFS to mount for `aptly` persistent state and scratch storage
# SIGNING_KEY_ADDR= dev@algorand.com or similar for GPG key
# RSTAMP= `scripts/reverse_hex_timestamp`
# AWS_ACCESS_KEY_ID=
# AWS_SECRET_ACCESS_KEY=

date "+build_release start %Y%m%d_%H%M%S"

set -e
set -x

if [ -z "${S3_PREFIX}" ]; then
    S3_PREFIX=s3://algorand-builds
fi

# persistent storage of repo manager scratch space is on EFS
if [ ! -z "${AWS_EFS_MOUNT}" ]; then
    if mount|grep -q /data; then
	echo /data already mounted
    else
	sudo mkdir -p /data
	sudo mount -t nfs4 -o nfsvers=4.1,rsize=1048576,wsize=1048576,hard,timeo=600,retrans=2,noresvport "${AWS_EFS_MOUNT}":/ /data
	# make environment for release_deb.sh
	sudo mkdir -p /data/_aptly
	sudo chown -R ${USER} /data/_aptly
	export APTLY_DIR=/data/_aptly
    fi
fi

export GOPATH=${HOME}/go
export PATH=${HOME}/gpgbin:${GOPATH}/bin:/usr/local/go/bin:${PATH}

cd ${GOPATH}/src/github.com/algorand/go-algorand
export RELEASE_GENESIS_PROCESS=true
export TRANSITION_TELEMETRY_BUILDS=true
PLATFORM=$(./scripts/osarchtype.sh)
PLATFORM_SPLIT=(${PLATFORM//\// })
OS=${PLATFORM_SPLIT[0]}
ARCH=${PLATFORM_SPLIT[1]}
export BRANCH=rel/stable
export CHANNEL=$(./scripts/compute_branch_channel.sh ${BRANCH})
export DEFAULTNETWORK=$(./scripts/compute_branch_network.sh)
export PKG_ROOT=${HOME}/node_pkg
export VARIATIONS="base"
# tell underlying 'build' scripts we already built
export NO_BUILD=true
if [ -z "${RSTAMP}" ]; then
    RSTAMP=$(scripts/reverse_hex_timestamp)
fi

# Update version file for this build
BUILD_NUMBER=
if [ -e buildnumber.dat ]; then
    BUILD_NUMBER=$(cat ./buildnumber.dat)
    BUILD_NUMBER=$((${BUILD_NUMBER} + 1))
else
    BUILD_NUMBER=0
fi
echo ${BUILD_NUMBER} > ./buildnumber.dat
export FULLVERSION=$(./scripts/compute_build_number.sh -f)

# a bash user might `source build_env` to manually continue a broken build
cat <<EOF>${HOME}/build_env
export RELEASE_GENESIS_PROCESS=${RELEASE_GENESIS_PROCESS}
export TRANSITION_TELEMETRY_BUILDS=${TRANSITION_TELEMETRY_BUILDS}
PLATFORM=${PLATFORM}
OS=${OS}
ARCH=${ARCH}
export BRANCH=${BRANCH}
export CHANNEL=${CHANNEL}
export DEFAULTNETWORK=${DEFAULTNETWORK}
export PKG_ROOT=${PKG_ROOT}
export VARIATIONS=${VARIATIONS}
RSTAMP=${RSTAMP}
BUILD_NUMBER=${BUILD_NUMBER}
export FULLVERSION=${FULLVERSION}
EOF
# strip leading 'export ' for docker --env-file
sed 's/^export //g' < ${HOME}/build_env > ${HOME}/build_env_docker

# Build!
scripts/configure_dev.sh

make ${GOPATH}/src/github.com/algorand/go-algorand/crypto/lib/libsodium.a

make build

scripts/build_packages.sh "${PLATFORM}"

# Run RPM bulid in Centos7 Docker container
sg docker "docker build -t algocentosbuild - < scripts/centos-build.Dockerfile"

# cleanup our libsodium build
if [ -f ${GOPATH}/src/github.com/algorand/go-algorand/crypto/libsodium-fork/Makefile ]; then
    (cd ${GOPATH}/src/github.com/algorand/go-algorand/crypto/libsodium-fork && make distclean)
fi
rm -rf ${GOPATH}/src/github.com/algorand/go-algorand/crypto/lib

# do the RPM build
sg docker "docker run --env-file ${HOME}/build_env_docker --mount type=bind,src=${GOPATH}/src,dst=/root/go/src --mount type=bind,src=${HOME},dst=/root/subhome --mount type=bind,src=/usr/local/go,dst=/usr/local/go -a stdout -a stderr algocentosbuild /root/go/src/github.com/algorand/go-algorand/scripts/build_release_centos_docker.sh"

# Tag Source
git add -A
git commit -m "Build ${BUILD_NUMBER}"

TAG=${BRANCH}-${FULLVERSION}
if [ ! -z "${SIGNING_KEY_ADDR}" ]; then
    git tag -s -u "${SIGNING_KEY_ADDR}" ${TAG} -m "Genesis Timestamp: $(cat ./genesistimestamp.dat)"
else
    git tag -s ${TAG} -m "Genesis Timestamp: $(cat ./genesistimestamp.dat)"
fi
git push origin ${TAG}

git archive --prefix=algorand-${FULLVERSION}/ "${TAG}" | gzip > ${PKG_ROOT}/algorand_${CHANNEL}_source_${FULLVERSION}.tar.gz

# create *.sig gpg signatures
cd ${PKG_ROOT}
for i in *.tar.gz *.deb *.rpm; do
    gpg --detach-sign "${i}"
done
HASHFILE=hashes_${CHANNEL}_${OS}_${ARCH}_${FULLVERSION}
rm -f "${HASHFILE}"
touch "${HASHFILE}"
md5sum *.tar.gz *.deb *.rpm >> "${HASHFILE}"
shasum -a 256 *.tar.gz *.deb *.rpm >> "${HASHFILE}"
shasum -a 512 *.tar.gz *.deb *.rpm >> "${HASHFILE}"
gpg --detach-sign "${HASHFILE}"
gpg --clearsign "${HASHFILE}"

echo RSTAMP=${RSTAMP} > "${HOME}/rstamp"
aws s3 sync --quiet --exclude dev\* --exclude master\* --exclude nightly\* --exclude stable\* --acl public-read ./ ${S3_PREFIX}/${CHANNEL}/${RSTAMP}_${FULLVERSION}/

# copy .rpm file to intermediate yum repo scratch space, actual publish manually later
if [ ! -d /data/yumrepo ]; then
    sudo mkdir -p /data/yumrepo
    sudo chown ${USER} /data/yumrepo
fi
cp -p -n *.rpm *.rpm.sig /data/yumrepo

cd ${HOME}
STATUSFILE=build_status_${CHANNEL}_${FULLVERSION}
echo "ami-id:" > "${STATUSFILE}"
curl --silent http://169.254.169.254/latest/meta-data/ami-id >> "${STATUSFILE}"
cat <<EOF>>"${STATUSFILE}"


go version:
EOF
go version >>"${STATUSFILE}"
cat <<EOF>>"${STATUSFILE}"

go env:
EOF
go env >>"${STATUSFILE}"
cat <<EOF>>"${STATUSFILE}"

build_env:
EOF
cat <${HOME}/build_env>>"${STATUSFILE}"
cat <<EOF>>"${STATUSFILE}"

dpkg-l:
EOF
dpkg -l >>"${STATUSFILE}"
gpg --clearsign "${STATUSFILE}"
gzip "${STATUSFILE}.asc"
aws s3 cp --quiet "${STATUSFILE}.asc.gz" "s3://algorand-devops-misc/buildlog/${RSTAMP}/${STATUSFILE}.asc.gz"

# use aptly to push .deb to its serving repo
# Leave .deb publishing to manual step after we do more checks on the release artifacts.
# ${GOPATH}/src/github.com/algorand/go-algorand/scripts/release_deb.sh ${PKG_ROOT}/*deb

# TODO: manually post rpm to repo

date "+build_release finish %Y%m%d_%H%M%S"
