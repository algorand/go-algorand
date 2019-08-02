#!/bin/bash
#
# test ubuntu install from inside docker image
#
# expects docker run with:
# --env-file ${HOME}/build_env_docker
# --mount type=bind,src=${HOME}/centos,dst=/stuff
# --mount type=bind,src=${GOPATH}/src,dst=/root/go/src
# --mount type=bind,src=/usr/local/go,dst=/usr/local/go

set -e
set -x

export GOPATH=${HOME}/go
export PATH=${GOPATH}/bin:/usr/local/go/bin:${PATH}

apt-get update
apt-get install -y gnupg2 curl software-properties-common python3

if [ "${TEST_UPGRADE}" == "no" ]; then
    echo "upgrade test skipped"
else
    apt install -y /stuff/*.deb
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

#apt-key adv --fetch-keys https://releases.algorand.com/key.pub
apt-key add /stuff/key.pub
add-apt-repository "deb http://${DC_IP}:8111/ stable main"
apt-get update
apt-get install -y algorand
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

echo UBUNTU_DOCKER_TEST_OK
