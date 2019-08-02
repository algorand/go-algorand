#!/bin/bash
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

set -e
set -x

export HOME=/root
mkdir -p ${HOME}/go
mkdir -p ${HOME}/go/bin
export GOPATH=${HOME}/go
export PATH=${GOPATH}/bin:/usr/local/go/bin:${PATH}

# Anchor our repo root reference location
REPO_ROOT="$( cd "$(dirname "$0")" ; pwd -P )"/../..

go install golang.org/x/lint/golint
go install github.com/golang/dep/cmd/dep
go install golang.org/x/tools/cmd/stringer
go install github.com/go-swagger/go-swagger/cmd/swagger


cd ${REPO_ROOT}

# definitely rebuild libsodium which could link to external C libraries
if [ -f ${REPO_ROOT}/crypto/libsodium-fork/Makefile ]; then
    (cd ${REPO_ROOT}/crypto/libsodium-fork && make distclean)
fi
rm -rf ${REPO_ROOT}/crypto/lib
make crypto/lib/libsodium.a

make build

export NO_BUILD=1

RPMTMP=$(mktemp -d 2>/dev/null || mktemp -d -t "rpmtmp")
trap "rm -rf ${RPMTMP}" 0
scripts/build_rpm.sh ${RPMTMP}
cp -p ${RPMTMP}/*/*.rpm /root/subhome/node_pkg

(cd ${HOME} && tar jxf /stuff/gnupg*.tar.bz2)
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
(cd ~/.gnupg && ln -s /S.gpg-agent S.gpg-agent)

gpg --import /stuff/key.pub
gpg --import ${REPO_ROOT}/installer/rpm/RPM-GPG-KEY-Algorand

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

NEWEST_RPM=$(ls -t /root/subhome/node_pkg/*rpm|head -1)
python2 "${HOME}/rpmsign.py" "${NEWEST_RPM}"

cp -p "${NEWEST_RPM}" /dummyrepo
createrepo --database /dummyrepo
rm -f /dummyrepo/repodata/repomd.xml.asc
gpg -u rpm@algorand.com --detach-sign --armor /dummyrepo/repodata/repomd.xml

OLDRPM=$(ls -t /stuff/*.rpm|head -1)
if [ -f "${OLDRPM}" ]; then
    yum install -y "${OLDRPM}"
    algod -v
    if algod -v | grep -q ${FULLVERSION}; then
	echo "already installed current version. wat?"
	false
    fi

    mkdir -p /root/testnode
    cp -p /var/lib/algorand/genesis/testnet/genesis.json /root/testnode

    goal node start -d /root/testnode
    goal node wait -d /root/testnode -w 120
    goal node stop -d /root/testnode
fi


yum-config-manager --add-repo http://${DC_IP}:8111/algodummy.repo

yum install -y algorand
algod -v
# check that the installed version is now the current version
algod -v | grep -q ${FULLVERSION}.${CHANNEL}

if [ ! -d /root/testnode ]; then
    mkdir -p /root/testnode
    cp -p /var/lib/algorand/genesis/testnet/genesis.json /root/testnode
fi

goal node start -d /root/testnode
goal node wait -d /root/testnode -w 120
goal node stop -d /root/testnode


echo CENTOS_DOCKER_TEST_OK
