#!/usr/bin/env bash

set -ex

# Check that the installed version is now the current version.
algod -v | grep -q "${VERSION}.${CHANNEL}"

mkdir -p /root/testnode
cp -p /var/lib/algorand/genesis.json /root/testnode

goal node start -d /root/testnode
goal node wait -d /root/testnode -w 120
goal node stop -d /root/testnode

