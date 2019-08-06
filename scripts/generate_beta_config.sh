#!/bin/bash

set -e

export GOPATH=$(go env GOPATH)
SRCPATH=${GOPATH}/src/github.com/algorand/go-algorand
cd ${SRCPATH}

make

CHANNEL=beta
RECIPE=${SRCPATH}/gen/networks/betanet/source/recipe.json
OUTPUT=${SRCPATH}/gen/networks/betanet/config

rm -rf ${OUTPUT}

mkdir -p ${OUTPUT}/genesisdata
cp ${SRCPATH}/gen/betanet/* ${OUTPUT}/genesisdata/
rm ${OUTPUT}/genesisdata/genesis.dump

${GOPATH}/bin/netgoal build --recipe "${RECIPE}" -n betanet -r "${OUTPUT}" --use-existing-files --force

echo Uploading configuration package for channel ${CHANNEL}
S3_RELEASE_BUCKET=algorand-internal scripts/upload_config.sh ${OUTPUT} ${CHANNEL}
