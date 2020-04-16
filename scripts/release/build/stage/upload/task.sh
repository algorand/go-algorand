#!/usr/bin/env bash
# shellcheck disable=1090,2129
# AWS_EFS_MOUNT= NFS to mount for `aptly` persistent state and scratch storage

set -ex

echo
date "+build_release begin UPLOAD stage %Y%m%d_%H%M%S"
echo

. "${HOME}/build_env"

cd "${PKG_ROOT}"

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

# Note this file is scp'd in stage/upload.sh
dpkg -l >> "${STATUSFILE}"
gpg --clearsign "${STATUSFILE}"
gzip -c "${STATUSFILE}".asc > "${HOME}"/node_pkg/"${STATUSFILE}".asc.gz

echo
date "+build_release end UPLOAD stage %Y%m%d_%H%M%S"
echo

