#!/usr/bin/env bash
# shellcheck disable=2012
# sign centos rpm from inside docker

set -ex

export HOME=/root
mkdir -p ${HOME}/go
mkdir -p ${HOME}/go/bin
export GOPATH=${HOME}/go
export PATH=${GOPATH}/bin:/usr/local/go/bin:${PATH}

GIT_REPO_PATH=https://github.com/btoll/go-algorand
mkdir -p "${HOME}/go/src/github.com/algorand"
#cd "${HOME}/go/src/github.com/algorand" && git clone --single-branch --branch "${HASH}" "${GIT_REPO_PATH}" go-algorand
cd "${HOME}/go/src/github.com/algorand" && git clone --single-branch --branch rel/stable "${GIT_REPO_PATH}" go-algorand

# Get golang 1.12 and build its own copy of go-algorand.
cd "${HOME}"
python3 "${HOME}/go/src/github.com/algorand/go-algorand/scripts/get_latest_go.py" --version-prefix=1.12
bash -c "cd /usr/local && tar zxf ${HOME}/go*.tar.gz"
(cd ${HOME} && tar jxf /root/stuff/gnupg*.tar.bz2)

REPO_DIR=/root/subhome/ben-branch
# Build!
"${REPO_DIR}"/scripts/configure_dev-deps.sh
make crypto/lib/libsodium.a -C "${REPO_DIR}"
make build -C "${REPO_DIR}"

RPMTMP=$(mktemp -d 2>/dev/null || mktemp -d -t "rpmtmp")
trap 'rm -rf ${RPMTMP}' 0
"${REPO_DIR}/scripts/release/test/build_rpm.sh" "${RPMTMP}"
mkdir -p /root/subhome/node_pkg
cp -p "${RPMTMP}"/*/*.rpm /root/subhome/node_pkg

export PATH="${HOME}/gnupg2/bin:${PATH}"
export LD_LIBRARY_PATH=${HOME}/gnupg2/lib

umask 0077
mkdir -p ~/.gnupg
umask 0022

touch "${HOME}/.gnupg/gpg.conf"
if grep -q no-autostart "${HOME}/.gnupg/gpg.conf"; then
    echo ""
else
    echo "no-autostart" >> "${HOME}/.gnupg/gpg.conf"
fi
rm -f ${HOME}/.gnupg/S.gpg-agent
(cd ~/.gnupg && ln -s /root/S.gpg-agent S.gpg-agent)

gpg --import /root/stuff/dev.pub
gpg --import /root/stuff/rpm.pub
rpmkeys --import /root/stuff/rpm.pub
echo "wat" | gpg -u rpm@algorand.com --clearsign

cat <<EOF>"${HOME}/.rpmmacros"
%_gpg_name Algorand RPM <rpm@algorand.com>
%__gpg ${HOME}/gnupg2/bin/gpg
%__gpg_check_password_cmd true
EOF

cat <<EOF>"${HOME}/rpmsign.py"
import rpm
import sys
rpm.addSign(sys.argv[1], '')
EOF

NEWEST_RPM=$(ls -t /root/subhome/node_pkg/*rpm | head -1)
python2 "${HOME}/rpmsign.py" "${NEWEST_RPM}"

cp -p "${NEWEST_RPM}" /dummyrepo
createrepo --database /dummyrepo
rm -f /dummyrepo/repodata/repomd.xml.asc
gpg -u rpm@algorand.com --detach-sign --armor /dummyrepo/repodata/repomd.xml

