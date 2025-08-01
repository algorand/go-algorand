#!/usr/bin/env bash

set -exo pipefail

# Ensure the centos docker image is built and available

DOCKER_IMAGE="algorand/go-algorand-ci-linux-centos10:amd64-$(sha1sum scripts/configure_dev-deps.sh | cut -f1 -d' ')"
MATCH=${DOCKER_IMAGE/:*/}

echo "Checking for RPM image"
if docker images $DOCKER_IMAGE | grep -qs $MATCH > /dev/null 2>&1; then
  echo "Image exists"
else
  echo "RPM image doesn't exist, building"
  docker build --platform=linux/amd64 --build-arg ARCH=amd64 \
    --build-arg GOLANG_VERSION=$(./scripts/get_golang_version.sh) -t $DOCKER_IMAGE -f docker/build/cicd.centos10.Dockerfile .
fi
