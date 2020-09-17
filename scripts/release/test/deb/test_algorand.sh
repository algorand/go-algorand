#!/usr/bin/env bash
# shellcheck disable=2045

set -ex

export GOPATH="$HOME/go"
export PATH="$GOPATH/bin:/usr/local/go/bin:$PATH"

PKG_NAME=algorand
if [ "$CHANNEL" = beta ]; then
    PKG_NAME=algorand-beta
fi

apt-get update
apt-get install -y gnupg2 curl software-properties-common python3

for deb in $(ls /root/subhome/node_pkg/*.deb); do
    if [[ ! "$deb" =~ devtools ]]; then
        apt-get install -y "$deb"
        algod -v

        mkdir -p /root/testnode
        cp -p /var/lib/algorand/genesis/testnet/genesis.json /root/testnode

        goal node start -d /root/testnode
        goal node wait -d /root/testnode -w 120
        goal node stop -d /root/testnode

        apt-key add /root/keys/dev.pub
        apt-key add /root/keys/rpm.pub
        add-apt-repository "deb http://${DC_IP}:8111/ stable main"
        apt-get update
        apt-get install -y "$PKG_NAME"

        if [ ! -d /root/testnode ]; then
            mkdir -p /root/testnode
            cp -p /var/lib/algorand/genesis/testnet/genesis.json /root/testnode
        fi

        goal node start -d /root/testnode
        goal node wait -d /root/testnode -w 120
        goal node stop -d /root/testnode
    fi
done

echo UBUNTU_DOCKER_TEST_OK

