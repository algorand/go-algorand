#!/usr/bin/env bash
# shellcheck disable=1090,2012
#
# build centos rpm from inside docker
#
# mount src from outside
# --mount type=bind,src=${GOPATH}/src,dst=/root/go/src
#
# mount golang install from outside
# --mount type=bind,src=/usr/local/go,dst=/usr/local/go
#
# output copied to /root/subhome/node_pkg
# --mount type=bind,src=${HOME},dst=/root/subhome

set -ex

export HOME=/root

. "${HOME}"/subhome/build_env

GIT_REPO_PATH=https://github.com/algorand/go-algorand
mkdir -p "${HOME}/go/src/github.com/algorand"
cd "${HOME}/go/src/github.com/algorand" && git clone --single-branch --branch "${HASH}" "${GIT_REPO_PATH}" go-algorand

# Get golang 1.12 and build its own copy of go-algorand.
cd "${HOME}"
python3 "${HOME}/go/src/github.com/algorand/go-algorand/scripts/get_latest_go.py" --version-prefix=1.12
bash -c "cd /usr/local && tar zxf ${HOME}/go*.tar.gz"

GOPATH=$(/usr/local/go/bin/go env GOPATH)
export PATH=${HOME}/gpgbin:${GOPATH}/bin:/usr/local/go/bin:${PATH}
export GOPATH

REPO_DIR=/root/go/src/github.com/algorand/go-algorand

# Build!
"${REPO_DIR}"/scripts/configure_dev-deps.sh
make crypto/lib/libsodium.a -C "${REPO_DIR}"
make build -C "${REPO_DIR}"

cd "${REPO_DIR}"

# definitely rebuild libsodium which could link to external C libraries
#if [ -f ${REPO_DIR}/crypto/libsodium-fork/Makefile ]; then
#    make distclean --directory ${REPO_DIR}/crypto/libsodium-fork
#fi
#rm -rf ${REPO_DIR}/crypto/lib
#make crypto/lib/libsodium.a
#
#make build

RPMTMP=$(mktemp -d 2>/dev/null || mktemp -d -t "rpmtmp")
trap 'rm -rf ${RPMTMP}' 0
"${REPO_DIR}/scripts/release/helper/build_rpm.sh" "${RPMTMP}"
cp -p "${RPMTMP}"/*/*.rpm /root/subhome/node_pkg

(cd ${HOME} && tar jxf /root/stuff/gnupg*.tar.bz2)
export PATH="${HOME}/gnupg2/bin:${PATH}"
export LD_LIBRARY_PATH=${HOME}/gnupg2/lib

umask 0077
mkdir -p "${HOME}/.gnupg"
umask 0022
touch "${HOME}/.gnupg/gpg.conf"
if grep -q no-autostart "${HOME}/.gnupg/gpg.conf"; then
    echo ""
else
    echo "no-autostart" >> "${HOME}/.gnupg/gpg.conf"
fi
rm -f ${HOME}/.gnupg/S.gpg-agent
(cd ~/.gnupg && ln -s /S.gpg-agent S.gpg-agent)

gpg --import /root/stuff/key.pub
gpg --import /root/stuff/rpm.pub
#gpg --import ${REPO_DIR}/installer/rpm/RPM-GPG-KEY-Algorand
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

cp -p "${NEWEST_RPM}" /root/dummyrepo
createrepo --database /root/dummyrepo
rm -f /root/dummyrepo/repodata/repomd.xml.asc
gpg -u rpm@algorand.com --detach-sign --armor /root/dummyrepo/repodata/repomd.xml

OLDRPM=$(ls -t /root/stuff/*.rpm | head -1)
if [ -f "${OLDRPM}" ]; then
    yum install -y "${OLDRPM}"
    algod -v
    if algod -v | grep -q "${FULLVERSION}"
    then
        echo "already installed current version. wat?"
        false
    fi

    mkdir -p /root/testnode
    cp -p /var/lib/algorand/genesis/testnet/genesis.json /root/testnode

    goal node start -d /root/testnode
    goal node wait -d /root/testnode -w 120
    goal node stop -d /root/testnode
fi

yum-config-manager --add-repo "http://${DC_IP}:8111/algodummy.repo"

yum install -y algorand
algod -v
# check that the installed version is now the current version
algod -v | grep -q "${FULLVERSION}.${CHANNEL}"

if [ ! -d /root/testnode ]; then
    mkdir -p /root/testnode
    cp -p /var/lib/algorand/genesis/testnet/genesis.json /root/testnode
fi

goal node start -d /root/testnode
goal node wait -d /root/testnode -w 120
goal node stop -d /root/testnode

echo CENTOS_DOCKER_TEST_OK

