#!/bin/bash
. ${HOME}/build_env
set -e
set -x

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

# Anchor our repo root reference location
REPO_ROOT="$( cd "$(dirname "$0")" ; pwd -P )"/..

cd ${REPO_ROOT}

. ${HOME}/build_env
git push origin
git push origin ${TAG}

cd ${PKG_ROOT}

if [ ! -z "${S3_PREFIX}" ]; then
    aws s3 sync --quiet --exclude dev\* --exclude master\* --exclude nightly\* --exclude stable\* --acl public-read ./ ${S3_PREFIX}/${CHANNEL}/${RSTAMP}_${FULLVERSION}/
fi

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
if [ ! -z "${S3_PREFIX_BUILDLOG}" ]; then
    aws s3 cp --quiet "${STATUSFILE}.asc.gz" "${S3_PREFIX_BUILDLOG}/${RSTAMP}/${STATUSFILE}.asc.gz"
fi

date "+build_release done uploading %Y%m%d_%H%M%S"

# NEXT: release_deb.sh
