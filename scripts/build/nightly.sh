#!/usr/bin/env bash
set -e

export GOPATH=$(go env GOPATH)

# Flag that we want release handling of genesis files
export RELEASE_GENESIS_PROCESS=true

# Clone repo to temp location
REPO_DIR=$(mktemp -d 2>/dev/null || mktemp -d -t "tmp")

git clone https://github.com/algorand/go-algorand ${REPO_DIR}
pushd ${REPO_DIR}

git checkout rel/nightly
git merge origin/master -m "FI from master"

# Update version file for this build
BUILD_NUMBER=
if [ -e buildnumber.dat ]; then
    BUILD_NUMBER=$(cat ./buildnumber.dat)
    BUILD_NUMBER=$((${BUILD_NUMBER} + 1))
else
    BUILD_NUMBER=0
fi
echo ${BUILD_NUMBER} > ./buildnumber.dat

git add ./genesistimestamp.dat ./buildnumber.dat
git commit -m "Build ${BUILD_NUMBER} Data"
git push

TAG=rel/nightly-$(scripts/compute_build_number.sh -f)
git tag -a ${TAG} -m "Genesis Timestamp: $(cat ./genesistimestamp.dat)"
git push origin ${TAG}

popd
rm -rf ${REPO_DIR}
