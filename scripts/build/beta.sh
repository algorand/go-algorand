#!/usr/bin/env bash
set -ev

GOPATH=$(go env GOPATH)
REPO_DIR=${GOPATH}/src/github.com/algorand/go-algorand
cd ${REPO_DIR}

# Flag that we want release handling of genesis files
export RELEASE_GENESIS_PROCESS=true

git checkout rel/beta

# Update version file for this build
BUILD_NUMBER=
if [ -e buildnumber.dat ]; then
    BUILD_NUMBER=$(cat ./buildnumber.dat)
    BUILD_NUMBER=$((${BUILD_NUMBER} + 1))
else
    BUILD_NUMBER=0
fi
echo ${BUILD_NUMBER} > ./buildnumber.dat

# Build before committing - the pre-commit checks can fail otherwise
make

git add -A
git commit -m "Build ${BUILD_NUMBER}"
git push
