#!/usr/bin/env bash
<<<<<<< HEAD:scripts/release/helper/deb_test.sh

#set -xv
=======
>>>>>>> rel/beta:scripts/release/test/deb/test_apt-get.sh

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
<<<<<<< HEAD:scripts/release/helper/deb_test.sh
OUTPUT=$(expect -d /workdir/testDebian.exp /var/lib/algorand /testdata)
=======
OUTPUT=$(expect -d /workdir/deb/testDebian.exp /var/lib/algorand /testdata)
>>>>>>> rel/beta:scripts/release/test/deb/test_apt-get.sh
STATUS=$?
echo "$OUTPUT"

echo "test_apt-get completed with status: " $STATUS

exit $STATUS

