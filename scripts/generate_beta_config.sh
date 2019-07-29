#!/bin/bash

set -e

export GOPATH=$(go env GOPATH)
SRCPATH=${GOPATH}/src/github.com/algorand/go-algorand
cd ${SRCPATH}

make

CHANNEL=beta
RECIPE=${SRCPATH}/gen/networks/beta/source/recipe.json
OUTPUT=${SRCPATH}/gen/networks/beta/config

rm -rf ${OUTPUT}

mkdir -p ${OUTPUT}/genesisdata
cp ${SRCPATH}/gen/beta/* ${OUTPUT}/genesisdata/
rm ${OUTPUT}/genesisdata/genesis.dump

${GOPATH}/bin/netgoal build --recipe "${RECIPE}" -n beta -r "${OUTPUT}" --use-existing-files --force

echo Uploading configuration package for channel ${CHANNEL}
scripts/upload_config.sh ${OUTPUT} ${CHANNEL}
