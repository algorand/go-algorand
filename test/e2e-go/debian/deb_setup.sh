#!/bin/bash
set -x
set -v

echo "deb_setup starting"

cp /var/lib/algorand/genesis/devnet/genesis.json /var/lib/algorand/genesis.json
algod -v

systemctl status algorand.service 
systemctl start algorand.service
systemctl status algorand.service

OUTPUT=$(
 expect -d /workdir/testDebian.exp /var/lib/algorand /usr/bin
)
STATUS=$?
echo $OUTPUT

systemctl stop algorand.service 
systemctl status algorand.service

echo "deb_setup completed with status: " $STATUS

exit $STATUS
