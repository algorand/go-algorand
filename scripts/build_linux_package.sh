#!/bin/bash

set -e

# Anchor our repo root reference location
REPO_ROOT="$( cd "$(dirname "$0")" ; pwd -P )"/..

cd ${REPO_ROOT}

# Delete tmp folder so we don't include that in our context
rm -rf ./tmp
docker build -f ./go-algorand/algorand/build/Dockerfile -t algorand-build .
docker rm buildpkg || true
docker run --name buildpkg algorand-build
mkdir -p ./tmp/dev_linux_pkg
docker cp buildpkg:/go/src/github.com/algorand/go-algorand/tmp/dev_pkg ./tmp/dev_linux_pkg
docker stop buildpkg
