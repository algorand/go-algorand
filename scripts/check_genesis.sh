#!/usr/bin/env bash

# Generate gen files into a temp folder for comparison
# then ensure we delete that folder on exit to clean up.
TEMPDIR=$(mktemp -d 2>/dev/null || mktemp -d -t "tmp")
trap "rm -rf ${TEMPDIR}" 0
mkdir -p ${TEMPDIR}/gen

GOPATH=$(go env GOPATH)

if [ "${DEFAULTNETWORK}" = "" ]; then
    DEFAULTNETWORK=$(./scripts/compute_branch_network.sh)
fi

# Copy existing wallet files so genesis reuses them as it will normally.
cp gen/${DEFAULTNETWORK}/*.partkey gen/${DEFAULTNETWORK}/*.rootkey ${TEMPDIR}/gen/

${GOPATH}/bin/genesis -d ${TEMPDIR}/gen -n ${DEFAULTNETWORK} -c gen/${DEFAULTNETWORK}.json >/dev/null

cmp -s gen/${DEFAULTNETWORK}/genesis.json ${TEMPDIR}/gen/genesis.json
if [ $? -ne 0 ]; then
    echo "genesis.json output doesn't match expected; please yell at David and run `touch gen/generate.go && make`"
    exit 1
fi

# Generate genesis.dump to compare too
./scripts/dump_genesis.sh gen/${DEFAULTNETWORK}/genesis.json > ${TEMPDIR}/gen/genesis.dump

cmp -s gen/${DEFAULTNETWORK}/genesis.dump ${TEMPDIR}/gen/genesis.dump
if [ $? -ne 0 ]; then
    echo "genesis.dump output doesn't match expected; please run `make dump`"
    exit 1
fi
