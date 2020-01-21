#!/usr/bin/env bash
# shellcheck disable=1090,2129
# AWS_EFS_MOUNT= NFS to mount for `aptly` persistent state and scratch storage

echo
date "+build_release begin UPLOAD stage %Y%m%d_%H%M%S"
echo

. "${HOME}/build_env"
set -ex

#AWS_EFS_MOUNT=fs-31159fd2.efs.us-east-1.amazonaws.com

# persistent storage of repo manager scratch space is on EFS
if [ ! -z "${AWS_EFS_MOUNT}" ]; then
    if mount | grep -q /data
    then
        echo /data already mounted
    else
        sudo mkdir -p /data
        sudo mount -t nfs4 -o nfsvers=4.1,rsize=1048576,wsize=1048576,hard,timeo=600,retrans=2,noresvport "${AWS_EFS_MOUNT}":/ /data
        # make environment for release_deb.sh
        sudo mkdir -p /data/_aptly
        sudo chown -R "${USER}" /data/_aptly
        export APTLY_DIR=/data/_aptly
    fi
fi

cd "${PKG_ROOT}"

# copy .rpm file to intermediate yum repo scratch space, actual publish manually later
if [ ! -d /data/yumrepo ]; then
    sudo mkdir -p /data/yumrepo
    sudo chown "${USER}" /data/yumrepo
fi

# For an explanation of the "./*.rpm" below
# see https://github.com/koalaman/shellcheck/wiki/SC2035
cp -p -n ./*.rpm ./*.rpm.sig /data/yumrepo

cd "${HOME}"
STATUSFILE=build_status_${CHANNEL}_${FULLVERSION}

echo "ami-id:" > "${STATUSFILE}"
curl --silent http://169.254.169.254/latest/meta-data/ami-id >> "${STATUSFILE}"

############################################################

cat <<EOF>>"${STATUSFILE}"


go version:
EOF

/usr/local/go/bin/go version >>"${STATUSFILE}"


############################################################

cat <<EOF>>"${STATUSFILE}"

go env:
EOF

/usr/local/go/bin/go env >>"${STATUSFILE}"

############################################################

cat <<EOF>>"${STATUSFILE}"

build_env:
EOF

cat <"${HOME}"/build_env >> "${STATUSFILE}"

############################################################

cat <<EOF>>"${STATUSFILE}"

dpkg-l:
EOF

############################################################

dpkg -l >> "${STATUSFILE}"
gpg --clearsign "${STATUSFILE}"
gzip "${STATUSFILE}".asc

"${REPO_ROOT}"/scripts/release/helper/release_deb.sh

echo
date "+build_release end UPLOAD stage %Y%m%d_%H%M%S"
echo

