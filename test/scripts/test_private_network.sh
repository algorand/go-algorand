#!/usr/bin/env bash
echo "######################################################################"
echo "  test_private_network"
echo "######################################################################"

set -e
set -o pipefail
set -o nounset

# Suppress telemetry reporting for tests
export ALGOTEST=1

export GOPATH=$(go env GOPATH)
SRCPATH=$(pwd)

NETROOTPATH=${SRCPATH}/tmp/test_private_network
GENFILESPATH=${SRCPATH}/tmp/test_private_network_genesis_files

# purge if it already exists
${GOPATH}/bin/goal network delete -r ${NETROOTPATH} || true
rm -rf ${NETROOTPATH}
rm -rf ${GENFILESPATH}

${GOPATH}/bin/goal network create -r ${NETROOTPATH} -n net1 -t ./test/testdata/nettemplates/TwoNodes50Each.json

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
${GOPATH}/bin/goal network genesis -r ${GENFILESPATH} -t ./test/testdata/nettemplates/TwoNodes50Each.json
# Try importing genesis files from same template -- should reuse the root and partkey files
${GOPATH}/bin/goal network create -r ${NETROOTPATH} -n net1 -t ./test/testdata/nettemplates/TwoNodes50Each.json --genesisDir ${GENFILESPATH}

${GOPATH}/bin/goal network start -r ${NETROOTPATH}

${GOPATH}/bin/goal network stop -r ${NETROOTPATH}

${GOPATH}/bin/goal network delete -r ${NETROOTPATH}

# Creating genesis files should fail if directory is not empty
# Capture output upon failure
RES=$(${GOPATH}/bin/goal network genesis -r ${GENFILESPATH} 2>&1 || true)
EXPERROR="already exists and is not empty"
if [[ $RES != *"${EXPERROR}"* ]]; then
    date '+test_private_network FAIL goal network genesis did not fail even though specified directory was not empty %Y%m%d_%H%M%S'
    exit 1
fi

echo "----------------------------------------------------------------------"
echo "  DONE: test_private_network"
echo "----------------------------------------------------------------------"
