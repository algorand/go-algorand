#!/usr/bin/env bash

# deploy_linux_version.sh - Compiles the current branch on macos using docker
#
# Syntax:   deploy_linux_version [-t temporary staging directory]
#
# Outputs:  <errors or warnings>
#
# ExitCode: 0 = Success - new version built and uploaded
#

set -e

export GOPATH=$(go env GOPATH)

# Anchor our repo root reference location
REPO_ROOT="$( cd "$(dirname "$0")" ; pwd -P )"/..

cd ${REPO_ROOT}
SRCPATH=${REPO_ROOT}

TMPDIR="${SRCPATH}/tmp"

while [ "$1" != "" ]; do
    case "$1" in
        -t)
            shift
            if [[ "$1" ==  "${TMPDIR}"* ]]; then
                TMPDIR=$1
            else
                echo "Provided temporary directory '$1' need to be a located under ${TMPDIR}"
                exit 2
            fi
            ;;
        *)
            echo "Unknown option" "$1"
            exit 1
            ;;
    esac
    shift
done

if [ "${AWS_ACCESS_KEY_ID}" = "" ] || [ "${AWS_SECRET_ACCESS_KEY}" = "" ] || [ "${S3_RELEASE_BUCKET}" = "" ]; then
    echo "You need to export AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY and S3_RELEASE_BUCKET for this to work"
    exit 1
fi

# Delete tmp folder so we don't include that in our context
rm -rf ${TMPDIR}
mkdir -p ${TMPDIR}

# If using custom genesis file, make sure it's copied to the image
if [[ "${GENESISFILE}" != "" ]]; then
    cp "${GENESISFILE}" ${TMPDIR}/${CHANNEL}.json
    GENESISFILE=${TMPDIR#"$SRCPATH/"}/${CHANNEL}.json
fi

# Since we don't know what our actual in-docker-build path is, we need to accommodate extra required /.. to root ourselves
SUBDIR=${TMPDIR#"$SRCPATH/"}
SUBDIRCOUNT=$(echo "${SUBDIR}" | tr -cd '/' | wc -c)
RELPATHXTRA=$(printf -v UPDIR '%*s' ${SUBDIRCOUNT} ''; echo ${UPDIR// /\/..})

echo \#!/bin/bash > ${TMPDIR}/deploy_linux_version_exec.sh
echo SCRIPTPATH='$( cd "$(dirname "$0")" ; pwd -P )' >> ${TMPDIR}/deploy_linux_version_exec.sh
echo cd \${SCRIPTPATH}/..${RELPATHXTRA} >> ${TMPDIR}/deploy_linux_version_exec.sh
echo export BRANCH=${BRANCH} >> ${TMPDIR}/deploy_linux_version_exec.sh
echo export CHANNEL=${CHANNEL} >> ${TMPDIR}/deploy_linux_version_exec.sh
echo export DEFAULTNETWORK=${DEFAULTNETWORK} >> ${TMPDIR}/deploy_linux_version_exec.sh
echo export GENESISFILE=${GENESISFILE} >> ${TMPDIR}/deploy_linux_version_exec.sh
echo export FULLVERSION=${FULLVERSION} >> ${TMPDIR}/deploy_linux_version_exec.sh
echo export PKG_ROOT=${PKG_ROOT} >> ${TMPDIR}/deploy_linux_version_exec.sh
echo export AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID} >> ${TMPDIR}/deploy_linux_version_exec.sh
echo export AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY} >> ${TMPDIR}/deploy_linux_version_exec.sh
echo export S3_RELEASE_BUCKET=${S3_RELEASE_BUCKET} >> ${TMPDIR}/deploy_linux_version_exec.sh
echo export NETWORK=${NETWORK} >> ${TMPDIR}/deploy_linux_version_exec.sh

echo scripts/deploy_private_version.sh -c \"${CHANNEL}\" -g \"${DEFAULTNETWORK}\" -n \"${NETWORK}\" -f \"${GENESISFILE}\" -b \"${S3_RELEASE_BUCKET}\" >> ${TMPDIR}/deploy_linux_version_exec.sh
chmod +x ${TMPDIR}/deploy_linux_version_exec.sh

if ! ./scripts/check_golang_version.sh
then
    exit 1
fi
# Get the go build version.
GOLANG_VERSION=$(./scripts/get_golang_version.sh)

sed "s|TMPDIR|${SUBDIR}|g" ${SRCPATH}/docker/build/Dockerfile-deploy > ${TMPDIR}/Dockerfile-deploy
docker build -f ${TMPDIR}/Dockerfile-deploy --build-arg GOLANG_VERSION="${GOLANG_VERSION}" -t algorand-deploy .
