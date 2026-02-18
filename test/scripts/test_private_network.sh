#!/usr/bin/env bash

set -euf -o pipefail

echo "######################################################################"
echo "  test_private_network"
echo "######################################################################"

# Suppress telemetry reporting for tests
export ALGOTEST=1

export GOPATH=$(go env GOPATH)
SRCPATH=$(pwd)

NETROOTPATH=${SRCPATH}/tmp/test_private_network
# purge if it already exists
${GOPATH}/bin/goal network delete -r ${NETROOTPATH} || true
rm -rf ${NETROOTPATH}

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

echo "----------------------------------------------------------------------"
echo "  DONE: test_private_network"
echo "----------------------------------------------------------------------"
