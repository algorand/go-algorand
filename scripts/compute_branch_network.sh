#!/usr/bin/env bash

export GOPATH=$(go env GOPATH)
cd "$(dirname "$0")"/..

if [ "$1" != "" ]; then
    BRANCH="$1"
else
    BRANCH=$(./scripts/compute_branch.sh)
fi

if [ "${BRANCH}" = "rel/stable" ]; then
    echo "testnet"
    exit 0
fi

#get parent of current branch
#credit to https://stackoverflow.com/questions/3161204/find-the-parent-branch-of-a-git-branch
BRANCHPARENT="$(git show-branch | grep '\*' | grep -v '${BRANCH}' | head -n1 | sed 's/.*\[\(.*\)\].*/\1/' | sed 's/[\^~].*//' || ${BRANCH})"
BRANCHPARENT=${BRANCHPARENT-$BRANCH}

if [ "${BRANCHPARENT}" = "rel/stable" ]; then
    echo "testnet"
elif [ "${BRANCHPARENT}" = "rel/beta" ]; then
    echo "betanet"
else
    echo "devnet"
fi

