#!/usr/bin/env bash

set -ex

SCRIPTPATH="$( cd "$(dirname "$0")" ; pwd -P )"
${SCRIPTPATH}/deploy_private_version.sh -c beta -n betanet -f ${SCRIPTPATH}/../installer/genesis/betanet/betanet-v1.0.json -b algorand-internal
