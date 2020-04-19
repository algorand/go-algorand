#!/usr/bin/env bash
# shellcheck disable=2064

set -ex

echo
date "+build_release begin PACKAGE DOCKER stage %Y%m%d_%H%M%S"
echo

OS_TYPE="$1"
ARCH="$2"
WORKDIR="$3"

if [ -z "$OS_TYPE" ] || [ -z "$ARCH" ] || [ -z "$WORKDIR" ]; then
    echo OS, ARCH and WORKDIR variables must be defined.
    exit 1
fi

export REPO_DIR="$WORKDIR"
BRANCH=$("$REPO_DIR/scripts/compute_branch.sh")
export BRANCH
CHANNEL=$("$REPO_DIR/scripts/compute_branch_channel.sh" "$BRANCH")
export CHANNEL

mkdir -p "$REPO_DIR/tmp/node_pkgs/$OS_TYPE/$ARCH/pkg"
TARBALLS="$REPO_DIR/tmp/node_pkgs/$OS_TYPE/$ARCH"
export OUTDIR="$TARBALLS/pkg"
BRANCH=$("$REPO_DIR/scripts/compute_branch.sh")
export BRANCH
CHANNEL=$("$REPO_DIR/scripts/compute_branch_channel.sh" "$BRANCH")
export CHANNEL
FULLVERSION=$("$REPO_DIR/scripts/compute_build_number.sh" -f)
export FULLVERSION

PKG_ROOT=$(mktemp -d)
trap "rm -rf $PKG_ROOT" 0

mkdir -p "$PKG_ROOT/usr/bin"

ALGOD_INSTALL_TAR_FILE="$TARBALLS/node_${CHANNEL}_${OS_TYPE}-${ARCH}_${FULLVERSION}.tar.gz"

if [ -f "$ALGOD_INSTALL_TAR_FILE" ]; then
    echo "using install file $ALGOD_INSTALL_TAR_FILE"
else
    echo "error, $ALGOD_INSTALL_TAR_FILE does not exist"
    exit 1
fi

INPUT_ALGOD_TAR_FILE="temp_install.tar.gz"
CHANNEL_VERSION="${CHANNEL}_${FULLVERSION}"
PKG_DIR="algod_pkg_$CHANNEL_VERSION"
DOCKER_EXPORT_FILE="algod_docker_export_$CHANNEL_VERSION.tar.gz"
DOCKER_PKG_FILE="algod_docker_package_$CHANNEL_VERSION.tar.gz"
DOCKER_IMAGE="algorand/algod_$CHANNEL_VERSION:latest"
DOCKERFILE="$REPO_DIR/docker/build/algod.Dockerfile"
START_ALGOD_FILE="$REPO_DIR/docker/release/start_algod_docker.sh"

echo "building '$DOCKERFILE' with install file $ALGOD_INSTALL_TAR_FILE"
cp "$ALGOD_INSTALL_TAR_FILE" "./$INPUT_ALGOD_TAR_FILE"
docker build --build-arg ALGOD_INSTALL_TAR_FILE="$INPUT_ALGOD_TAR_FILE" . -t "$DOCKER_IMAGE" -f "$DOCKERFILE"

#echo "pushing '${DOCKER_IMAGE}'"
#docker push ${DOCKER_IMAGE}

mkdir -p "$PKG_DIR"

echo "exporting image '$DOCKER_IMAGE' to file '$DOCKER_EXPORT_FILE'"
docker save --output "$PKG_DIR/$DOCKER_EXPORT_FILE" "$DOCKER_IMAGE"

dockerExportStatus=$?
if [ "$dockerExportStatus" -ne 0 ]; then
    echo "Error exporting docker image: $dockerExportStatus"
    exit "$dockerExportStatus"
fi

echo "creating docker package tar file $DOCKER_PKG_FILE"
cp "$START_ALGOD_FILE" "$PKG_DIR/"
cp "$REPO_DIR/docker/release/deploy_README.md" "$PKG_DIR/README.md"
sed -i.bak "s/%CHANNEL_VERSION%/$CHANNEL_VERSION/g" "$PKG_DIR/$START_ALGOD_FILE" && rm "$PKG_DIR/$START_ALGOD_FILE.bak"

tar cvf "$DOCKER_PKG_FILE" "$PKG_DIR"

echo "moving resulting docker package to ${OUTDIR}${DOCKER_PKG_FILE}"
mkdir -p "$OUTDIR"
cp "$DOCKER_PKG_FILE" "$OUTDIR"

echo "cleaning up temporary files"
rm ./"$INPUT_ALGOD_TAR_FILE"
rm ./"$DOCKER_PKG_FILE"
rm -rf "$PKG_DIR"

echo
date "+build_release end PACKAGE DOCKER stage %Y%m%d_%H%M%S"
echo

