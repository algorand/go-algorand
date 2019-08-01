#!/usr/bin/env bash
set -ev

GOPATH=$(go env GOPATH)
REPO_DIR=${GOPATH}/src/github.com/algorand/go-algorand
cd ${REPO_DIR}

# Run `make` to ensure `buildtools` is available
make -j4

# Flag that we want release handling of genesis files
export RELEASE_GENESIS_PROCESS=true

git checkout rel/beta

# Disabled because we have static genesis files now
#NETWORKS=("testnet" "mainnet")
#for NETWORK in "${NETWORKS[@]}"; do
#    ${GOPATH}/bin/buildtools genesis ensure --release -n ${NETWORK} --source ${REPO_DIR}/gen/${NETWORK}/genesis.json  --releasedir ${REPO_DIR}/installer/genesis
#    git add ${REPO_DIR}/installer/genesis/${NETWORK}/*
#done

# Update version file for this build
BUILD_NUMBER=
if [ -e buildnumber.dat ]; then
    BUILD_NUMBER=$(cat ./buildnumber.dat)
else
    BUILD_NUMBER=0
fi
BUILD_NUMBER=$((${BUILD_NUMBER} + 1))
echo ${BUILD_NUMBER} > ./buildnumber.dat

# Build before committing - the pre-commit checks can fail otherwise
make

git add -A
git commit -m "Build ${BUILD_NUMBER}"
git push

TAG=rel/beta-$(scripts/compute_build_number.sh -f)
if [ ! -z "${SIGNING_KEY_ADDR}" ]; then
    git tag -s -u "${SIGNING_KEY_ADDR}" ${TAG} -m "Genesis Timestamp: $(cat ./genesistimestamp.dat)"
else
    git tag -a ${TAG} -m "Genesis Timestamp: $(cat ./genesistimestamp.dat)"
fi
git push origin ${TAG}
