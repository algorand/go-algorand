#!/usr/bin/env bash

set -ex

apt-get install -y "$WORKDIR/pkg"/*.deb
algod -v

mkdir -p /root/testnode
cp -p /var/lib/algorand/genesis/testnet/genesis.json /root/testnode

#goal node start -d /root/testnode
#goal node wait -d /root/testnode -w 120
#goal node stop -d /root/testnode
#
#apt-key add /root/keys/dev.pub
#apt-key add /root/keys/rpm.pub
#add-apt-repository "deb http://127.0.0.1:8111/ stable main"
#apt-get update
#apt-get install algorand -y
#algod -v
## check that the installed version is now the current version
#algod -v | grep -q "${FULLVERSION}.${CHANNEL}"
#
#if [ ! -d /root/testnode ]; then
#    mkdir -p /root/testnode
#    cp -p /var/lib/algorand/genesis/testnet/genesis.json /root/testnode
#fi

goal node start -d /root/testnode
goal node wait -d /root/testnode -w 120
goal node stop -d /root/testnode

echo UBUNTU_DOCKER_TEST_OK

