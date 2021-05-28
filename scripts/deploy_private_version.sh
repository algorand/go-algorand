#!/usr/bin/env bash

# deploy_private_version.sh - Performs a complete build/packaging of a specific branch, for specified platforms.
#
# Syntax:   deploy_private_version -c <channel> [ -g <genesis-network> | -f <genesis-file> ] -n <network>
#
# Outputs:  <errors or warnings>
#
# ExitCode: 0 = Success - new version built and uploaded
#
# Usage:    Can be used locally to publish a local build for testing
#
# Examples: scripts/deploy_private_version.sh -c TestCatchup -g testnet -n testnetwork
#
# Notes:    If you're running on a Mac, this will attempt to use docker to build for linux.
#           GenesisNetwork currently must be either testnet or devnet -- use -f for a custom genesis.json file

set -e

export GOPATH=$(go env GOPATH)

# Anchor our repo root reference location
REPO_ROOT="$( cd "$(dirname "$0")" ; pwd -P )"/..

export SRCPATH=${REPO_ROOT}
cd ${SRCPATH}

CHANNEL=""
DEFAULTNETWORK=""
NETWORK=""
GENESISFILE=""
BUCKET=""

while [ "$1" != "" ]; do
    case "$1" in
        -c)
            shift
            CHANNEL=$1
            ;;
        -g)
            shift
            DEFAULTNETWORK=$1
            ;;
        -n)
            shift
            NETWORK=$1
            ;;
        -f)
            shift
            GENESISFILE=$1
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

if [[ "${CHANNEL}" = "" || "${NETWORK}" = "" || "${DEFAULTNETWORK}" = "" && "${GENESISFILE}" = "" ]]; then
    echo "Syntax: deploy_private_version -c <channel> [ -g <genesis-network> | -f <genesis-file> ] -n <network> [ -b <bucket> ]"
    echo "e.g. deploy_private_version.sh -c TestCatchup -g testnet -n testnetwork"
    exit 1
fi

# Don't use environment variable for S3_RELEASE_BUCKET - default to algorand-internal for private deployments
if [[ ! -z "${S3_RELEASE_BUCKET}" && -z "${BUCKET}" ]]; then
    echo "Ignoring S3_RELEASE_BUCKET setting - defaulting to algorand-internal.  Use -b to override."
fi
S3_RELEASE_BUCKET="${BUCKET:-algorand-internal}"

# If GENESISFILE specified, DEFAULTNETWORK doesn't really matter but we need to ensure we have one
if [[ "${DEFAULTNETWORK}" = "" ]]; then
    DEFAULTNETWORK=devnet
elif [[ "${DEFAULTNETWORK}" != "devnet" && "${DEFAULTNETWORK}" != "testnet" ]]; then
    echo "genesis-network needs to be either devnet or testnet"
    exit 1
fi

export BRANCH=$(./scripts/compute_branch.sh)
export CHANNEL=${CHANNEL}
export DEFAULTNETWORK=${DEFAULTNETWORK}
export FULLVERSION=$(./scripts/compute_build_number.sh -f)
export PKG_ROOT=${HOME}/node_pkg
export S3_RELEASE_BUCKET=${S3_RELEASE_BUCKET}

if [[ $(uname) == "Darwin" ]]; then
    export NETWORK=${NETWORK}
    export GENESISFILE=${GENESISFILE}
    scripts/deploy_linux_version.sh -t ${SRCPATH}/tmp/${NETWORK}
    exit
fi

# modify genesis.json to use a custom network name to prevent SRV record resolving
TEMPDIR=$(mktemp -d 2>/dev/null || mktemp -d -t "tmp")
cp installer/genesis/${DEFAULTNETWORK}/genesis.json ${TEMPDIR}
# make directory to hold genesis.json file
mkdir -p "gen/${DEFAULTNETWORK}"
echo "cp ${TEMPDIR}/genesis.json gen/${DEFAULTNETWORK};rm -rf ${TEMPDIR}"
trap "cp ${TEMPDIR}/genesis.json gen/${DEFAULTNETWORK};rm -rf ${TEMPDIR}" 0
echo "if genesis file then sed in GENESISFILE=${GENESISFILE}"
if [[ "${GENESISFILE}" = "" ]]; then
    echo "${GENESISFILE} was empty"
    echo "sed s/${DEFAULTNETWORK}/${NETWORK}/ ${TEMPDIR}/genesis.json > gen/${DEFAULTNETWORK}/genesis.json"
    sed "s/${DEFAULTNETWORK}/${NETWORK}/" ${TEMPDIR}/genesis.json > gen/${DEFAULTNETWORK}/genesis.json
else
    echo "${GENESISFILE} not empty"

    cp ${GENESISFILE} gen/${DEFAULTNETWORK}/genesis.json
fi

# For private builds, always build the base version (with telemetry)
export VARIATIONS="base"
scripts/build_packages.sh $(./scripts/osarchtype.sh)

scripts/upload_version.sh ${CHANNEL} ${PKG_ROOT} ${S3_RELEASE_BUCKET}
