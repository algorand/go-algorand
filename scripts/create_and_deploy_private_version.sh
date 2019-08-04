#!/bin/bash

# create_and_deploy_private_version.sh - Generates deployed network configuration and private build and pushes to S3
#
# Syntax:   create_and_deploy_private_version.sh -c <channel> -n <network> --config <network config> -t <template> [ -r <rootdir> ] [ -h <hosttemplates-file> ]"
#
# Outputs:  <errors or warnings>
#
# ExitCode: 0 = Success - new version built and uploaded
#
# Usage:    Generates deployed network configuration (nodecfg package) and cloudspec.config (for TF/algonet),
#           sends it to S3, then uses the deploy_private_version script to build the private version with the
#           correct genesis file and uploads it to S3.
#
# Examples: create_and_deploy_private_version.sh -c TestCatchup -n testnetwork \
#               --config test/testdata/deployednettemplates/configs/private-test.json -t test/testdata/deployednettemplates/networks/20Wallets3Relays5Nodes.json
#
# Notes:    If you're running on a Mac, this will attempt to use docker to build for linux.
#           If <rootdir> not specified, the generated network configurations are stored under test/testdata/networks
#           as assets for preservation / sharing / reference,

set -e

if [[ "${AWS_ACCESS_KEY_ID}" = "" || "${AWS_SECRET_ACCESS_KEY}" = "" ]]; then
    echo "You need to export AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY for this to work"
    exit 1
fi

SCRIPTPATH="$( cd "$(dirname "$0")" ; pwd -P )"
export GOPATH=$(go env GOPATH)

# Anchor our repo root reference location
REPO_ROOT=${SCRIPTPATH}/..

export SRCPATH=${REPO_ROOT}

CHANNEL=""
NETWORK=""
CONFIGFILE=""
TEMPLATEFILE=""
ROOTDIR=""
HOSTTEMPLATESSPEC=""
BUCKET=""

while [ "$1" != "" ]; do
    case "$1" in
        -c)
            shift
            CHANNEL=$1
            ;;
        -n)
            shift
            NETWORK=$1
            ;;
        --config)
            shift
            CONFIGFILE=$1
            ;;
        -t)
            shift
            TEMPLATEFILE=$1
            ;;
        -r)
            shift
            ROOTDIR=$1
            ;;
        -h)
            shift
            HOSTTEMPLATESSPEC="-H $1"
            ;;
        -b)
            shift
            BUCKET="$1"
            ;;
        *)
            echo "Unknown option" "$1"
            exit 1
            ;;
    esac
    shift
done

# if Network isn't specified, use the same string as Channel
if [[ "${NETWORK}" = "" ]]; then
    NETWORK=${CHANNEL}
fi

if [[ "${CHANNEL}" = "" || "${NETWORK}" = "" || "${CONFIGFILE}" = "" || "${TEMPLATEFILE}" = "" ]]; then
    echo "Syntax: create_and_deploy_private_version.sh -c <channel> -n <network> --config <network config> -t <template> [ -r <rootdir> ] [ -h <hosttemplates-file> ]"
    echo "e.g. create_and_deploy_private_version.sh -c TestCatchup -n testnetwork --config test/testdata/deployednettemplates/configs/private-test.json -t test/testdata/deployednettemplates/networks/20Wallets3Relays5Nodes.json"
    exit 1
fi

# Don't use environment variable for S3_RELEASE_BUCKET - default to algorand-internal for private deployments
if [[ ! -z "${S3_RELEASE_BUCKET}" && -z "${BUCKET}" ]]; then
    echo "Ignoring S3_RELEASE_BUCKET setting - defaulting to algorand-internal.  Use -b to override."
fi
S3_RELEASE_BUCKET="${BUCKET:-algorand-internal}"

# if rootdir not specified, default to storing in our repo for posterity / reference
if [[ "${ROOTDIR}" = "" ]]; then
    ROOTDIR=${SRCPATH}/test/testdata/networks/${NETWORK}
fi

# Build so we've got up-to-date binaries
(cd ${SRCPATH} && make)

# Generate the nodecfg package directory
${GOPATH}/bin/netgoal build -r "${ROOTDIR}" -n "${NETWORK}" -c "${CONFIGFILE}" -t "${TEMPLATEFILE}" ${HOSTTEMPLATESSPEC}

# Package and upload the config package
export S3_RELEASE_BUCKET="${S3_RELEASE_BUCKET}"
${SRCPATH}/scripts/upload_config.sh "${ROOTDIR}" "${CHANNEL}"

# Now generate a private build using our custom genesis.json and deploy it to S3 also
${SRCPATH}/scripts/deploy_private_version.sh -c "${CHANNEL}" -f "${ROOTDIR}/genesisdata/genesis.json" -n "${NETWORK}" -b "${S3_RELEASE_BUCKET}"
