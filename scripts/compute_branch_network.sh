#!/usr/bin/env bash

export GOPATH=$(go env GOPATH)
cd ${GOPATH}/src/github.com/algorand/go-algorand

# If enlistment isn't clean, it's 'dev'
./scripts/check_clean_enlistment.sh
if [ $? -ne 0 ]; then
    echo "devnet"
    exit 0
fi

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
BRANCHPARENT="$(git show-branch | grep '\*' | grep -v '${BRANCH}' | head -n1 | sed 's/.*\[\(.*\)\].*/\1/' | sed 's/[\^~].*//')"

if [ "${BRANCHPARENT}" = "rel/stable" ]; then
    echo "testnet"
elif [ "${BRANCHPARENT}" = "rel/beta" ]; then
    echo "betanet"
else
    echo "devnet"
fi

