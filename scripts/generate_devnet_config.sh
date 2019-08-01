#!/bin/bash

set -e

export GOPATH=$(go env GOPATH)
SRCPATH=$(pwd)

make

CHANNEL=nightly
CONFIG=${SRCPATH}/gen/networks/devnet/source/devnet.json
HOSTTEMPLATES=${SRCPATH}/gen/networks/devnet/source/hosttemplates.json
TOPOLOGY=${SRCPATH}/gen/networks/devnet/source/5Hosts5Relays20Nodes.json
OUTPUT=${SRCPATH}/gen/networks/devnet/config

rm -rf ${OUTPUT}

mkdir -p ${OUTPUT}/genesisdata
cp ${SRCPATH}/gen/devnet/* ${OUTPUT}/genesisdata/
rm ${OUTPUT}/genesisdata/genesis.dump

${GOPATH}/bin/netgoal build -c "${CONFIG}" -H "${HOSTTEMPLATES}" -n devnet -t "${TOPOLOGY}" -r "${OUTPUT}" --use-existing-files --force

echo Uploading configuration package for channel ${CHANNEL}
scripts/upload_config.sh ${OUTPUT} ${CHANNEL}
