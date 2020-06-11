#!/usr/bin/env bash

# upload_version.sh - Uploads available update packages
#           NOTE: Will only work if you have the required AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY vars set
#
# Syntax:   upload_version.sh <channel> <directory-with-packages> <bucket>
#
# Outputs:  <output from updater>
#
# ExitCode: 0 = Update succeeded
#
# Usage:    Should be used after build_packages.sh completes successfully
#           Currently called by deploy_version.sh
#
# Examples: scripts/upload_version.sh nightly $HOME/node_pkg/ algorand-releases

if [[ "$#" -lt 3 ]]; then
    echo "Syntax: upload_version <channel> <directory-with-packages> <bucket>"
    exit 1
fi

CHANNEL=$1
DIRECTORY=$2
BUCKET=$3

export GOPATH1=$(go env GOPATH | cut -d':' -f1 )
export PATH=${PATH}:${GOPATH1}/bin
updater send -s "${DIRECTORY}" -c "${CHANNEL}" -b "${BUCKET}"
