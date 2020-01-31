#!/usr/bin/env bash

#set -xv

echo "test_apt-get starting within docker container"

export GOPATH=${HOME}/go
export PATH=${GOPATH}/bin:/usr/local/go/bin:${PATH}

apt-get update
apt-get install -y gnupg2 curl software-properties-common python3
apt-key add /root/keys/dev.pub
add-apt-repository -y "deb [trusted=yes] http://${DC_IP}:8111/ stable main"
apt-get update
apt-get install -y algorand
apt-get install -y expect

algod -v

echo "starting test of algod with expect script testDebian.exp"
OUTPUT=$(expect -d /workdir/deb/testDebian.exp /var/lib/algorand /testdata)
STATUS=$?
echo "$OUTPUT"

echo "test_apt-get completed with status: " $STATUS

exit $STATUS

