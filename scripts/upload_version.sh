#!/bin/bash

# upload_version.sh - Uploads available update packages
#           NOTE: Will only work if you have the required AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY vars set
#
# Syntax:   upload_version.sh <channel> <directory-with-packages>
#
# Outputs:  <output from updater>
#
# ExitCode: 0 = Update succeeded
#
# Usage:    Should be used after build_packages.sh completes successfully
#           Currently called by deploy_version.sh
#
# Examples: scripts/upload_version.sh nightly $HOME/node_pkg/

if [[ "$#" -ne 2 && "$#" -ne 3 ]]; then
    echo "Syntax: upload_version <channel> <directory-with-packages> <optional: bucket>"
    exit 1
fi

CHANNEL=$1

export GOPATH=$(go env GOPATH)
if [[ "$#" -eq 2 ]]; then
    ${GOPATH}/bin/updater send -s "$2" -c ${CHANNEL}
else
    ${GOPATH}/bin/updater send -s "$2" -c ${CHANNEL} -b "$3"
fi
