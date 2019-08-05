#!/bin/bash

set -e

export GOPATH=$(go env GOPATH)
SRCPATH=$(pwd)

make

CHANNEL=stable
CONFIG=${SRCPATH}/gen/networks/testnet/source/testnet.json
HOSTTEMPLATES=${SRCPATH}/gen/networks/testnet/source/hosttemplates.json
TOPOLOGY=${SRCPATH}/gen/networks/testnet/source/5Hosts5Relays20Nodes.json
OUTPUT=${SRCPATH}/gen/networks/testnet/config
NETWORK=testnet

rm -rf ${OUTPUT}

mkdir -p ${OUTPUT}/genesisdata
cp ${SRCPATH}/gen/testnet/* ${OUTPUT}/genesisdata/
rm ${OUTPUT}/genesisdata/genesis.dump

${GOPATH}/bin/netgoal build -c "${CONFIG}" -H "${HOSTTEMPLATES}" -n ${NETWORK} -t "${TOPOLOGY}" -r "${OUTPUT}" --use-existing-files --force

echo Uploading configuration package for channel ${CHANNEL}
scripts/upload_config.sh ${OUTPUT} ${CHANNEL}
