#!/usr/bin/env bash
# shellcheck disable=2012

set -ex

OLDRPM=$(ls -t /root/subhome/node_pkg/*.rpm | head -1)
yum install -y "${OLDRPM}"

# Check that the installed version is now the current version.
algod -v | grep -q "${FULLVERSION}.${CHANNEL}"

mkdir -p /root/testnode
cp -p /var/lib/algorand/genesis/testnet/genesis.json /root/testnode

goal node start -d /root/testnode
goal node wait -d /root/testnode -w 120
goal node stop -d /root/testnode

