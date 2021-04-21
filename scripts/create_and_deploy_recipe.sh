#!/usr/bin/env bash

# create_and_deploy_recipe.sh - Generates deployed network configuration (based on a recipe) and private build and pushes to S3
#
# Syntax:   create_and_deploy_recipe.sh -c <channel/network> [-n network] --recipe <recipe file> -r <rootdir> [--nodeploy] [--skip-build] [--force] [-m genesisVersionModifier] [ -b <bucket> ]"
#
# Outputs:  <errors or warnings>
#
# ExitCode: 0 = Success - config generated and uploaded, and new version built and uploaded
#
# Usage:    Generates deployed network configuration (nodecfg package) and cloudspec.config (for TF/algonet),
#           sends it to S3, then uses the deploy_private_version script to build the private version with the
#           correct genesis file and uploads it to S3 (if --nodeply specified only the config is build and uploaded).
#
# Examples: create_and_deploy_recipe.sh -c TestCatchup --recipe test/testdata/deployednettemplates/recipes/devnet-like.config -r ~/networks/gen
#
# Notes:    If you're running on a Mac, this will attempt to use docker to build for linux.

set -e

if [[ "${AWS_ACCESS_KEY_ID}" = "" || "${AWS_SECRET_ACCESS_KEY}" = "" ]]; then
    echo "You need to export your AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY for this to work"
    exit 1
fi

SCRIPTPATH="$( cd "$(dirname "$0")" ; pwd -P )"
export GOPATH=$(go env GOPATH)

# Anchor our repo root reference location
REPO_ROOT=${SCRIPTPATH}/..

export SRCPATH=${REPO_ROOT}

CHANNEL=""
NETWORK=""
RECIPEFILE=""
ROOTDIR=""
NO_DEPLOY=""
FORCE_OPTION=""
SCHEMA_MODIFIER=""
BUCKET=""
SKIP_BUILD=""
BOOTSTRAP=""

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
        -m)
            shift
            SCHEMA_MODIFIER=$1
            ;;
        --recipe)
            shift
            RECIPEFILE=$1
            ;;
        -r)
            shift
            ROOTDIR=$1
            ;;
        --force)
            FORCE_OPTION="--force"
            ;;
        --nodeploy)
            NO_DEPLOY="true"
            ;;
        -b)
            shift
            BUCKET="$1"
            ;;
        --gendbfiles)
            BOOTSTRAP="true"
            ;;
        --skip-build)
            SKIP_BUILD="true"
            ;;
        *)
            echo "Unknown option" "$1"
            exit 1
            ;;
    esac
    shift
done

if [[ -z "${CHANNEL}" || -z "${RECIPEFILE}" || -z "${ROOTDIR}" ]]; then
    echo "Syntax: create_and_deploy_recipe.sh -c <channel/network> [-n network] --recipe <recipe file> -r <rootdir> [--nodeploy] [--force]"
    echo "e.g. create_and_deploy_recipe.sh -c TestCatchup --recipe test/testdata/deployednettemplates/recipes/devnet-like.config -r ~/networks/<channel>/gen"
    exit 1
fi

# Don't use environment variable for S3_RELEASE_BUCKET - default to algorand-internal for private deployments
if [[ ! -z "${S3_RELEASE_BUCKET}" && -z "${BUCKET}" ]]; then
    echo "Ignoring S3_RELEASE_BUCKET setting - defaulting to algorand-internal.  Use -b to override."
fi
S3_RELEASE_BUCKET="${BUCKET:-algorand-internal}"

# if Network isn't specified, use the same string as Channel
if [[ "${NETWORK}" = "" ]]; then
    NETWORK=${CHANNEL}
fi

# Build binaries
if [[ "${SKIP_BUILD}" != "true" || ! -f ${GOPATH}/bin/netgoal ]]; then
    # Build so we've got up-to-date binaries
    (cd ${SRCPATH} && make)
fi

# Generate the nodecfg package directory
${GOPATH}/bin/netgoal build -r "${ROOTDIR}" -n "${NETWORK}" --recipe "${RECIPEFILE}" "${FORCE_OPTION}" -m "${SCHEMA_MODIFIER}" -b=${BOOTSTRAP:-false}

# Package and upload the config package
export S3_RELEASE_BUCKET="${S3_RELEASE_BUCKET}"
${SRCPATH}/scripts/upload_config.sh "${ROOTDIR}" "${CHANNEL}"

NETWORK_PERF_RULES_PATH="$(dirname $RECIPEFILE)/network_performance_rules"

if [ -f "${NETWORK_PERF_RULES_PATH}" ]; then
    cp "${NETWORK_PERF_RULES_PATH}" "${ROOTDIR}/network_performance_rules"
fi

# Deploy binaries
if [ "${NO_DEPLOY}" = "" ]; then
    # Now generate a private build using our custom genesis.json and deploy it to S3 also
    ${SRCPATH}/scripts/deploy_private_version.sh -c "${CHANNEL}" -f "${ROOTDIR}/genesisdata/genesis.json" -n "${NETWORK}" -b "${S3_RELEASE_BUCKET}"
fi
