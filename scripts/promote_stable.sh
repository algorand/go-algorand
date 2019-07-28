#!/usr/bin/env bash

# promote_stable.sh - Promote the build for stable channel
#
# Syntax:   promote_stable.sh
#
# Usage:    Should only be used when officially releasing the build.
#           Requires AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY and S3_RELEASE_BUCKET to be defined in the env.
#
# Examples: scripts/promote_stable.sh

set -e

S3CMD="s3cmd"

function init_s3cmd() {
    SCRIPTPATH="$( cd "$(dirname "$0")" ; pwd -P )"
    SEDARGS="-e s,-ACCESS_KEY-,${AWS_ACCESS_KEY_ID}, -e s,-SECRET_KEY-,${AWS_SECRET_ACCESS_KEY}, -e s,-S3_BUCKET-,${S3_RELEASE_BUCKET},"

    cat ${SCRIPTPATH}/s3cfg.template \
      | sed ${SEDARGS} \
      > ${HOME}/.s3cfg

    if [[ "$(which s3cmd)" = "" ]]; then
        pushd ~/
        wget https://sourceforge.net/projects/s3tools/files/s3cmd/2.0.2/s3cmd-2.0.2.tar.gz
        tar -xf s3cmd-2.0.2.tar.gz
        popd
        S3CMD=~/s3cmd-2.0.2/s3cmd
    fi
}

init_s3cmd

CHANNEL="stable"

# Move the _${CHANNEL}_ files from the build to the release bucket
${S3CMD} ls s3://${S3_RELEASE_BUCKET}/channel/${CHANNEL}/ | grep _${CHANNEL}[_-] | awk '{ print $4 }' | while read line; do
    NEW_ARTIFACT_NAME=$(echo "$line" | sed -e "s/${BUILD_BUCKET}/${RELEASE_BUCKET}/g")
    echo "Copy ${line} => ${NEW_ARTIFACT_NAME}"
    ${S3CMD} cp ${line} ${NEW_ARTIFACT_NAME}
    echo "Deleting original file ${line}"
    ${S3CMD} rm ${line}
done
