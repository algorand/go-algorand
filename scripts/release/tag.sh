#!/usr/bin/env bash

# TODO: Ensure params are sent!
TAG=$1
BRANCH=${2:-rel/stable}

pushd "${HOME}"/go/src/github.com/algorand/go-algorand || exit
git checkout "${BRANCH}"

# TODO
# There should be a discussion about what we actually want in the git tag text.
# For now, just use the Unix timestamp.
git tag -s -u dev@algorand.com "${TAG}" -m "Genesis Timestamp: $(date +%s)"
git tag --verify "${TAG}"

git push -n --tags
git push --force --tags
popd

