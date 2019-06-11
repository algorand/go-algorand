#!/bin/bash

set -e

export GOPATH=$(go env GOPATH)
cd ${GOPATH}/src/github.com/algorand
SRCPATH=${GOPATH}/src/github.com/algorand/go-algorand

# Delete tmp folder so we don't include that in our context
rm -rf ${SRCPATH}/tmp
docker build -f ./go-algorand/docker/build/Dockerfile -t algorand-build .
docker rm buildpkg || true
docker run --name buildpkg algorand-build
mkdir -p ${SRCPATH}/tmp/dev_linux_pkg
docker cp buildpkg:/go/src/github.com/algorand/go-algorand/tmp/dev_pkg ${SRCPATH}/tmp/dev_linux_pkg
docker stop buildpkg
