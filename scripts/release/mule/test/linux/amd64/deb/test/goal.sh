#!/usr/bin/env bash

set -ex

apt-get install -y "$WORKDIR/pkg"/*.deb

# Check that the installed version is now the current version.
algod -v | grep -q "${VERSION}.${CHANNEL}"

mkdir -p /root/testnode
cp -p /var/lib/algorand/genesis/testnet/genesis.json /root/testnode

if [ ! -d /root/testnode ]; then
    mkdir -p /root/testnode
    cp -p /var/lib/algorand/genesis/testnet/genesis.json /root/testnode
fi

goal node start -d /root/testnode
goal node wait -d /root/testnode -w 120
goal node stop -d /root/testnode

