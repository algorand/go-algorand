#!/bin/bash

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
cd ${GOPATH}/src/github.com/algorand
SRCPATH=${GOPATH}/src/github.com/algorand/go-algorand

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


if [ "${S3_UPLOAD_ID}" = "" ] || [ "${S3_UPLOAD_SECRET}" = "" ] || [ "${S3_UPLOAD_BUCKET}" = "" ]; then
    echo "You need to export S3_UPLOAD_ID, S3_UPLOAD_SECRECT and S3_UPLOAD_BUCKET for this to work"
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

echo \#!/bin/bash > ${TMPDIR}/deploy_linux_version_exec.sh
echo SCRIPTPATH='$( cd "$(dirname "$0")" ; pwd -P )' >> ${TMPDIR}/deploy_linux_version_exec.sh
echo cd \${GOPATH}/src/github.com/algorand/go-algorand >> ${TMPDIR}/deploy_linux_version_exec.sh
echo export BRANCH=${BRANCH} >> ${TMPDIR}/deploy_linux_version_exec.sh
echo export CHANNEL=${CHANNEL} >> ${TMPDIR}/deploy_linux_version_exec.sh
echo export BUILDCHANNEL=${BUILDCHANNEL} >> ${TMPDIR}/deploy_linux_version_exec.sh
echo export DEFAULTNETWORK=${DEFAULTNETWORK} >> ${TMPDIR}/deploy_linux_version_exec.sh
echo export GENESISFILE=${GENESISFILE} >> ${TMPDIR}/deploy_linux_version_exec.sh
echo export FULLVERSION=${FULLVERSION} >> ${TMPDIR}/deploy_linux_version_exec.sh
echo export PKG_ROOT=${PKG_ROOT} >> ${TMPDIR}/deploy_linux_version_exec.sh
echo export S3_UPLOAD_ID=${S3_UPLOAD_ID} >> ${TMPDIR}/deploy_linux_version_exec.sh
echo export S3_UPLOAD_SECRET=${S3_UPLOAD_SECRET} >> ${TMPDIR}/deploy_linux_version_exec.sh
echo export S3_UPLOAD_BUCKET=${S3_UPLOAD_BUCKET} >> ${TMPDIR}/deploy_linux_version_exec.sh
echo export NETWORK=${NETWORK} >> ${TMPDIR}/deploy_linux_version_exec.sh

echo scripts/deploy_private_version.sh -c \"${CHANNEL}\" -g \"${DEFAULTNETWORK}\" -n \"${NETWORK}\" -f \"${GENESISFILE}\" >> ${TMPDIR}/deploy_linux_version_exec.sh
chmod +x ${TMPDIR}/deploy_linux_version_exec.sh

sed "s|TMPDIR|${TMPDIR#"$SRCPATH/"}|g" ${SRCPATH}/docker/build/Dockerfile-deploy > ${TMPDIR}/Dockerfile-deploy
docker build -f ${TMPDIR}/Dockerfile-deploy -t algorand-deploy .
