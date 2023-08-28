#!/usr/bin/env bash

set -euf -o pipefail

echo "######################################################################"
echo "  test_private_network"
echo "######################################################################"

if [ "$#" -eq 0 ]; then
  echo "Usage: test_private_network.sh <go-algorand SRCPATH>"
  exit 1
fi

# Suppress telemetry reporting for tests
export ALGOTEST=1

export GOPATH=$(go env GOPATH)
SRCPATH="$1"

NETROOTPATH=${SRCPATH}/tmp/test_private_network
GENFILESPATH=${SRCPATH}/tmp/test_private_network_genesis_files

# purge if it already exists
${GOPATH}/bin/goal network delete -r ${NETROOTPATH} || true
rm -rf ${NETROOTPATH}
rm -rf ${GENFILESPATH}

${GOPATH}/bin/goal network create -r ${NETROOTPATH} -n net1 -t ${SRCPATH}/test/testdata/nettemplates/TwoNodes50Each.json

${GOPATH}/bin/goal network start -r ${NETROOTPATH}

${GOPATH}/bin/goal network stop -r ${NETROOTPATH}

${GOPATH}/bin/goal network delete -r ${NETROOTPATH}

# default network with no template specified

rm -rf ${NETROOTPATH}

${GOPATH}/bin/goal network create -r ${NETROOTPATH}

${GOPATH}/bin/goal network start -r ${NETROOTPATH}

${GOPATH}/bin/goal network stop -r ${NETROOTPATH}

${GOPATH}/bin/goal network delete -r ${NETROOTPATH}

# Test that genesis generation works correctly
${GOPATH}/bin/goal network pregen -g ${GENFILESPATH} -t ${SRCPATH}/test/testdata/nettemplates/TwoNodes50Each.json
# Try importing genesis files from same template -- should reuse the root and partkey files
${GOPATH}/bin/goal network create -r ${NETROOTPATH} -n net1 -t ${SRCPATH}/test/testdata/nettemplates/TwoNodes50Each.json --genesisdir ${GENFILESPATH}

${GOPATH}/bin/goal network start -r ${NETROOTPATH}

${GOPATH}/bin/goal network stop -r ${NETROOTPATH}

${GOPATH}/bin/goal network delete -r ${NETROOTPATH}

# Creating genesis files should fail if directory is not empty
# Capture output upon failure
RES=$(${GOPATH}/bin/goal network pregen -g ${GENFILESPATH} 2>&1 || true)
EXPERROR="already exists and is not empty"
if [[ $RES != *"${EXPERROR}"* ]]; then
    date '+test_private_network FAIL goal network pregen did not fail even though specified directory was not empty %Y%m%d_%H%M%S'
    exit 1
fi

echo "----------------------------------------------------------------------"
echo "  DONE: test_private_network"
echo "----------------------------------------------------------------------"
