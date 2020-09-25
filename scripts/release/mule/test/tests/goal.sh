#!/usr/bin/env bash

set -ex

mkdir -p /root/testnode
cp -p /var/lib/algorand/genesis.json /root/testnode

goal node start -d /root/testnode
goal node wait -d /root/testnode -w 60
goal node stop -d /root/testnode

