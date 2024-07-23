#!/usr/bin/env bash
set -e
trap 'echo "ERROR: ${BASH_SOURCE}:${LINENO} ${BASH_COMMAND}"' ERR

# upload_config.sh - Archives and uploads a netgoal configuration package from a specified directory
#           NOTE: Will only work if you have the required AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY vars set
#
# Syntax:   upload_config.sh <config root directory> <channel>
#
# Outputs:  <output from updater>
#
# ExitCode: 0 = Update succeeded
#
# Usage:    Should be used to package and upload a prepared netgoal configuration directory.
#           Expects target S3 bucket to be set as S3_RELEASE_BUCKET environment variable.
#
# Examples: scripts/upload_config.sh ~/MyTest1 david-test

if [ "$#" -ne 2 ]; then
    echo "Syntax: upload_config <config root directory> <channel>"
    exit 1
fi

if [[ -z "${S3_RELEASE_BUCKET}" ]]; then
    echo "Target S3 bucket must be set as S3_RELEASE_BUCKET env var"
    exit 1
fi

export GOPATH=$(go env GOPATH)

SCRIPTPATH="$( cd "$(dirname "$0")" ; pwd -P )"
SRCPATH=${SCRIPTPATH}/..

export CHANNEL=$2
export FULLVERSION=$($SRCPATH/scripts/compute_build_number.sh -f)

# prevent ._* files from being included in the tarball
export COPYFILE_DISABLE=true

TEMPDIR=$(mktemp -d -t "upload_config.tmp.XXXXXX")
TARFILE=${TEMPDIR}/config_${CHANNEL}_${FULLVERSION}.tar.gz

cd $1
tar -zcf ${TARFILE} * >/dev/null

${GOPATH}/bin/updater send -s ${TEMPDIR} -c ${CHANNEL} -b "${S3_RELEASE_BUCKET}"
rm ${TARFILE}
