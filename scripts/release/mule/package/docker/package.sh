#!/usr/bin/env bash

set -ex

echo
date "+build_release begin PACKAGE DOCKER stage %Y%m%d_%H%M%S"
echo

ARCH_TYPE=$(./scripts/archtype.sh)
OS_TYPE=$(./scripts/ostype.sh)
BRANCH=${BRANCH:-$(./scripts/compute_branch.sh "$BRANCH")}
CHANNEL=${CHANNEL:-$(./scripts/compute_branch_channel.sh "$BRANCH")}
PKG_ROOT_DIR="./tmp/node_pkgs/$OS_TYPE/$ARCH_TYPE"
VERSION=${VERSION:-$(./scripts/compute_build_number.sh -f)}
ALGOD_INSTALL_TAR_FILE="$PKG_ROOT_DIR/node_${CHANNEL}_${OS_TYPE}-${ARCH_TYPE}_${VERSION}.tar.gz"

if [ -f "$ALGOD_INSTALL_TAR_FILE" ]; then
    echo "using install file $ALGOD_INSTALL_TAR_FILE"
else
    echo "error, $ALGOD_INSTALL_TAR_FILE does not exist"
    exit 1
fi

INPUT_ALGOD_TAR_FILE="temp_install.tar.gz"
CHANNEL_VERSION="${CHANNEL}_${VERSION}"
NEW_PKG_DIR="algod_pkg_$CHANNEL_VERSION"
DOCKER_EXPORT_FILE="algod_docker_export_$CHANNEL_VERSION.tar.gz"
DOCKER_PKG_FILE="algod_docker_package_$CHANNEL_VERSION.tar.gz"
DOCKER_IMAGE="algorand/algod_$CHANNEL_VERSION:latest"
DOCKERFILE="./docker/build/algod.Dockerfile"
START_ALGOD_FILE="./docker/release/start_algod_docker.sh"
ALGOD_DOCKER_INIT="./docker/release/algod_docker_init.sh"

if ! ./scripts/check_golang_version.sh
then
    exit 1
fi
# Get the go build version.
GOLANG_VERSION=$(./scripts/get_golang_version.sh)

echo "building '$DOCKERFILE' with install file $ALGOD_INSTALL_TAR_FILE"
cp "$ALGOD_INSTALL_TAR_FILE" "/tmp/$INPUT_ALGOD_TAR_FILE"
cp "$ALGOD_DOCKER_INIT" /tmp
docker build --build-arg ALGOD_INSTALL_TAR_FILE="$INPUT_ALGOD_TAR_FILE" --build-arg GOLANG_VERSION="${GOLANG_VERSION}" /tmp -t "$DOCKER_IMAGE" -f "$DOCKERFILE"

mkdir -p "/tmp/$NEW_PKG_DIR"

echo "exporting image '$DOCKER_IMAGE' to file '$DOCKER_EXPORT_FILE'"
docker save --output "/tmp/$NEW_PKG_DIR/$DOCKER_EXPORT_FILE" "$DOCKER_IMAGE"

DOCKER_EXPORT_STATUS=$?
if [ "$DOCKER_EXPORT_STATUS" -ne 0 ]; then
    echo "Error exporting docker image: $DOCKER_EXPORT_STATUS"
    exit "$DOCKER_EXPORT_STATUS"
fi

echo "creating docker package tar file $DOCKER_PKG_FILE"
cp "$START_ALGOD_FILE" "/tmp/$NEW_PKG_DIR/"
cp ./docker/release/deploy_README.md "/tmp/$NEW_PKG_DIR/README.md"
sed -i "s/%CHANNEL_VERSION%/$CHANNEL_VERSION/g" "/tmp/$NEW_PKG_DIR/start_algod_docker.sh"

tar cvf "/tmp/$DOCKER_PKG_FILE" "/tmp/$NEW_PKG_DIR"

echo "moving resulting docker package to ${PKG_ROOT_DIR}${DOCKER_PKG_FILE}"
cp "/tmp/$DOCKER_PKG_FILE" "$PKG_ROOT_DIR"

echo
date "+build_release end PACKAGE DOCKER stage %Y%m%d_%H%M%S"
echo

