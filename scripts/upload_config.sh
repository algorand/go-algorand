#!/bin/bash
set -e

# upload_config.sh - Archives and uploads a netgoal configuration package from a specified directory
#           NOTE: Will only work if you have the required AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY vars set
#
# Syntax:   upload_config.sh <config root directory> <channel>
#
# Outputs:  <output from updater>
#
# ExitCode: 0 = Update succeeded
#
# Usage:    Should be used to package and upload a prepared netgoal configuration directory
#
# Examples: scripts/upload_config.sh ~/MyTest1 david-test

if [ "$#" -ne 2 ]; then
    echo "Syntax: upload_config <config root directory> <channel>"
    exit 1
fi

export GOPATH=$(go env GOPATH)

export CHANNEL=$2
export FULLVERSION=$(./scripts/compute_build_number.sh -f)

TEMPDIR=$(mktemp -d 2>/dev/null || mktemp -d -t "tmp")
TARFILE=${TEMPDIR}/config_${CHANNEL}_${FULLVERSION}.tar.gz

cd $1
tar -zcf ${TARFILE} * >/dev/null 2>&1

${GOPATH}/bin/updater send -s ${TEMPDIR} -c ${CHANNEL} -b "${S3_RELEASE_BUCKET}"
rm ${TARFILE}
