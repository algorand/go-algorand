#!/usr/bin/env bash

# deploy_version.sh - Performs a complete build/packaging of a specific branch, for specified platforms.
#           Unless SkipCleanCheck is set in environment, it first requires a clean fully-sync'd
#           enlistment before it will proceed.
#
# Syntax:   deploy_version.sh <branch> <os>/<arch> [<os>/<arch> ...]
#
# Outputs:  <errors or warnings>
#
# ExitCode: 0 = Success - new version built and uploaded
#
# Usage:    Can be used locally or on Travis to generate and upload a new build for auto-updates.
#           Currently called by travis/deploy_packages.sh
#           Expects target S3 bucket to be set as S3_RELEASE_BUCKET environment variable.
#
# Examples: scripts/deploy_version.sh my/testbranch linux/amd64
#           scripts/deploy_version.sh my/testbranch linux/amd64 darwin/amd64
#
# Notes:    Currently you can only target your current platform, due to our CGO usage not yet being portable

set -e

if [ "$#" -lt 2 ]; then
    echo "Syntax: deploy_version <branch> <os>/<arch> ..."
    echo "e.g. deploy_version master darwin/amd64 linux/amd64"
    exit 1
fi

if [[ -z "${S3_RELEASE_BUCKET}" ]]; then
    echo "Target S3 bucket must be set as S3_RELEASE_BUCKET env var"
    exit 1
fi

export BRANCH=$1
shift
export CHANNEL=${CHANNEL:-$(./scripts/compute_branch_channel.sh "${BRANCH}")}
export FULLVERSION=$(./scripts/compute_build_number.sh -f)
export PKG_ROOT=${HOME}/node_pkg

if [ "${SkipCleanCheck}" = "" ]; then
    scripts/checkout_branch.sh ${BRANCH}
else
    echo "Skipping enlistment check.  Proceed with caution!"
fi

export VARIATIONS="base"
scripts/build_packages.sh $@

scripts/upload_version.sh ${CHANNEL} ${PKG_ROOT} ${S3_RELEASE_BUCKET}
