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

# Get branch that owns head commit
BRANCHPARENT="$(git branch --contains HEAD | grep -v 'HEAD' | head -n1 | grep -Eo '\w+(\/\w*)*')"

if [ "${BRANCHPARENT}" = "rel/stable" ]; then
    echo "testnet"
elif [ "${BRANCHPARENT}" = "rel/beta" ]; then
    echo "betanet"
else
    echo "devnet"
fi

