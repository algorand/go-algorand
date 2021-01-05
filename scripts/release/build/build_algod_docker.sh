#!/usr/bin/env bash
set -e
set -x

ALGOD_INSTALL_TAR_FILE=$1

if [[ -z "$CHANNEL" ]];
then
  echo 'Missing CHANNEL environment setting.'
  exit 1
fi
if [[ -z "$FULLVERSION" ]];
then
  echo 'Missing FULLVERSION environment setting.'
  exit 1
fi

if [[ $ALGOD_INSTALL_TAR_FILE == "" ]]
then
   echo "specify filepath of base install file"
   exit 1
fi

if [ -f "$ALGOD_INSTALL_TAR_FILE" ]; then
    echo "using install file $ALGOD_INSTALL_TAR_FILE"
else
    echo "error, $ALGOD_INSTALL_TAR_FILE does not exist"
    exit 1
fi

INPUT_ALGOD_TAR_FILE="temp_install.tar.gz"
CHANNEL_VERSION="${CHANNEL}_${FULLVERSION}"
PKG_DIR="algod_pkg_${CHANNEL_VERSION}"
DOCKER_EXPORT_FILE="algod_docker_export_${CHANNEL_VERSION}.tar.gz"
DOCKER_PKG_FILE="algod_docker_package_${CHANNEL_VERSION}.tar.gz"
DOCKER_TAG="latest"
DOCKER_IMAGE="algorand/algod_${CHANNEL_VERSION}:${DOCKER_TAG}"
RESULT_DIR="${HOME}/node_pkg/"
DOCKERFILE="${HOME}/go/src/github.com/algorand/go-algorand/docker/build/algod.Dockerfile"
START_ALGOD_FILE="start_algod_docker.sh"
pushd "${HOME}/go/src/github.com/algorand/go-algorand"
if ! ./scripts/check_golang_version.sh
then
    exit 1
fi
# Get the go build version.
GOLANG_VERSION=$(./scripts/get_golang_version.sh)
popd

echo "building '${DOCKERFILE}' with install file $ALGOD_INSTALL_TAR_FILE"
cp "${ALGOD_INSTALL_TAR_FILE}" "./${INPUT_ALGOD_TAR_FILE}"
docker build --build-arg ALGOD_INSTALL_TAR_FILE=${INPUT_ALGOD_TAR_FILE} --build-arg GOLANG_VERSION=${GOLANG_VERSION} . -t ${DOCKER_IMAGE} -f ${DOCKERFILE}

#echo "pushing '${DOCKER_IMAGE}'"
#docker push ${DOCKER_IMAGE}

mkdir -p ${PKG_DIR}

echo "exporting image '${DOCKER_IMAGE}' to file '${DOCKER_EXPORT_FILE}'"
docker save --output ${PKG_DIR}/${DOCKER_EXPORT_FILE} ${DOCKER_IMAGE}

dockerExportStatus=$?
if [ $dockerExportStatus -ne 0 ]; then
    echo "Error exporting docker image: $dockerExportStatus"
    exit $dockerExportStatus
fi

echo "creating docker package tar file ${DOCKER_PKG_FILE}"
cp ./${START_ALGOD_FILE} ${PKG_DIR}/
cp ./deploy_README.md ${PKG_DIR}/README.md
sed -i.bak "s/%CHANNEL_VERSION%/${CHANNEL_VERSION}/g" ${PKG_DIR}/${START_ALGOD_FILE} && rm ${PKG_DIR}/${START_ALGOD_FILE}.bak

tar cvf ${DOCKER_PKG_FILE} ${PKG_DIR}

echo "moving resulting docker package to ${RESULT_DIR}${DOCKER_PKG_FILE}"
mkdir -p ${RESULT_DIR}
cp ${DOCKER_PKG_FILE} ${RESULT_DIR}

echo "cleaning up temporary files"
rm ./${INPUT_ALGOD_TAR_FILE}
rm ./${DOCKER_PKG_FILE}
rm -rf ${PKG_DIR}


