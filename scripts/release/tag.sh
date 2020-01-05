#!/usr/bin/env bash

TAG=foo-bar
SIGNING_KEY_ADDR=dev@algorand.com

#  # Set the TIMESTAMP to use for the genesis.json file - set here so all packages use the same number
#  TIMESTAMP=
#  if [ -e ./genesistimestamp.dat ]; then
#      TIMESTAMP=$(cat ./genesistimestamp.dat)
#  else
#      TIMESTAMP=$(date +%s)
#  fi
#  export TIMESTAMP=${TIMESTAMP}

cd "${HOME}"/go/src/github.com/algorand/go-algorand || exit
git tag -d "${TAG}"
git checkout HEAD
git tag -s -u "${SIGNING_KEY_ADDR}" "${TAG}" -m "Genesis Timestamp: $(cat ./genesistimestamp.dat)"
git tag --verify "${TAG}"
git push -n --tags
git push --force --tags

