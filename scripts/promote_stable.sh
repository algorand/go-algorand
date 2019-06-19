#!/usr/bin/env bash

# promote_stable.sh - Promote the pending_* packages for stable channel
#
# Syntax:   promote_stable.sh
#
# Usage:    Should only be used when officially releasing the build.
#           Requires S3_UPLOAD_ID, S3_UPLOAD_SECRET and S3_UPLOAD_BUCKET to be defined in the env.
#
# Examples: scripts/promote_stable.sh

set -e

S3CMD="s3cmd"

function init_s3cmd() {
    SCRIPTPATH="$( cd "$(dirname "$0")" ; pwd -P )"
    SEDARGS="-e s,-ACCESS_KEY-,${S3_UPLOAD_ID}, -e s,-SECRET_KEY-,${S3_UPLOAD_SECRET}, -e s,-S3_BUCKET-,${S3_UPLOAD_BUCKET},"

    cat ${SCRIPTPATH}/s3cfg.template \
      | sed ${SEDARGS} \
      > ${HOME}/.s3cfg

    if [[ "$(which s3cmd)" = "" ]]; then
        pushd ~/
        wget https://sourceforge.net/projects/s3tools/files/s3cmd/2.0.2/s3cmd-2.0.2.tar.gz
        tar -xf s3cmd-2.0.2.tar.gz
        popd
        sudo apt-get install python-dateutil
        S3CMD=~/s3cmd-2.0.2/s3cmd
    fi
}

init_s3cmd

CHANNEL="stable"

# Rename the _CHANNEL_ and CHANNEL-VARIANT pending files
${S3CMD} ls s3://${S3_UPLOAD_BUCKET}/pending_ | grep _${CHANNEL}[_-] | awk '{ print $4 }' | while read line; do
    NEW_ARTIFACT_NAME=$(echo "$line" | sed -e 's/pending_//')
    echo "Rename ${line} => ${NEW_ARTIFACT_NAME}"
    ${S3CMD} mv ${line} ${NEW_ARTIFACT_NAME}
done
