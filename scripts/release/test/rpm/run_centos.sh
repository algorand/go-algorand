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

GOPATH=$(/usr/local/go/bin/go env GOPATH)
export PATH=${HOME}/gpgbin:${GOPATH}/bin:/usr/local/go/bin:${PATH}
export GOPATH

REPO_DIR=/root/go/src/github.com/algorand/go-algorand

cd "${REPO_DIR}"

(cd ${HOME} && tar jxf /root/keys/gnupg*.tar.bz2)
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
(cd ~/.gnupg && ln -s /root/S.gpg-agent S.gpg-agent)

gpg --import /root/keys/dev.pub
gpg --import /root/keys/rpm.pub
#gpg --import ${REPO_DIR}/installer/rpm/RPM-GPG-KEY-Algorand
rpmkeys --import /root/keys/rpm.pub
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

OLDRPM=$(ls -t /root/keys/*.rpm | head -1)
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

