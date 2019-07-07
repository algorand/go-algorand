#!/usr/bin/env bash

# release_packages.sh - Script executed by Travis for 'Release' step, if build / tests succeed
#
# Syntax:   release_packages.sh
#
# Usage:    Should only be used by Travis.
#
# Examples: scripts/travis/release_packages.sh

set -e

CHANNEL=""
FULLVERSION=""
S3CMD="s3cmd"

function init_s3cmd() {
    SCRIPTPATH="$( cd "$(dirname "$0")" ; pwd -P )"
    SEDARGS="-e s,-ACCESS_KEY-,${AWS_ACCESS_KEY_ID}, -e s,-SECRET_KEY-,${AWS_SECRET_ACCESS_KEY}, -e s,-S3_BUCKET-,${S3_RELEASE_BUCKET},"

    cat ${SCRIPTPATH}/../s3cfg.template \
      | sed ${SEDARGS} \
      > ${HOME}/.s3cfg

    CHANNEL=$(./scripts/compute_branch_channel.sh ${TRAVIS_BRANCH})
    FULLVERSION=$(./scripts/compute_build_number.sh -f)

    if [[ "$(which s3cmd)" = "" ]]; then
        pushd ~/
        wget https://sourceforge.net/projects/s3tools/files/s3cmd/2.0.2/s3cmd-2.0.2.tar.gz
        tar -xf s3cmd-2.0.2.tar.gz
        popd
        sudo apt-get install python-dateutil
        S3CMD=~/s3cmd-2.0.2/s3cmd
    fi
}

function promote_nightly() {
    init_s3cmd

    # Rename the _CHANNEL_ and _CHANNEL-VARIANT_ pending files
    ${S3CMD} ls s3://${S3_RELEASE_BUCKET}/pending_ | grep _${FULLVERSION}. | grep _${CHANNEL}[-_] | awk '{ print $4 }' | while read line
    do
        NEW_ARTIFACT_NAME=$(echo "$line" | sed -e 's/pending_//')
        echo "Copy ${line} => ${NEW_ARTIFACT_NAME}"
        ${S3CMD} cp ${line} ${NEW_ARTIFACT_NAME}
    done
}

function promote_stable() {
    init_s3cmd

    # Copy the _CHANNEL_ pending 'node' files to _CHANNEL-canary_
    ${S3CMD} ls s3://${S3_RELEASE_BUCKET}/pending_node_ | grep _${FULLVERSION}. | grep _${CHANNEL}_ | awk '{ print $4 }' | while read line
    do
        NEW_ARTIFACT_NAME=$(echo "$line" | sed -e 's/pending_//' | sed -e "s/_${CHANNEL}_/_${CHANNEL}-canary_/g")
        echo "Copy ${line} => ${NEW_ARTIFACT_NAME}"
        ${S3CMD} cp ${line} ${NEW_ARTIFACT_NAME}
    done
}

case "${TRAVIS_BRANCH}" in
    rel/nightly)
        promote_nightly
        ;;
    rel/stable)
        promote_stable
        ;;
esac
