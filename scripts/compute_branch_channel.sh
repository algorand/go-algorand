#!/usr/bin/env bash

# If workspace isn't clean, it's 'dev'.
BRANCH="$1"

if [ "${BRANCH}" = "master" ]; then
    echo "master"
    exit 0
elif [ "${BRANCH}" = "rel/nightly" ]; then
    echo "nightly"
    exit 0
elif [ "${BRANCH}" = "rel/stable" ]; then
    echo "stable"
    exit 0
elif [ "${BRANCH}" = "rel/beta" ]; then
    echo "beta"
    exit 0
elif [ "${BRANCH}" = "feature/alphanet" ]; then
    echo "alpha"
    exit 0
fi

#get parent of current branch
#credit to https://stackoverflow.com/questions/3161204/find-the-parent-branch-of-a-git-branch
BRANCHPARENT="$(git show-branch | grep '\*' | grep -v "${BRANCH}" | head -n1 | sed 's/.*\[\(.*\)\].*/\1/' | sed 's/[\^~].*//' || ${BRANCH})"
BRANCHPARENT=${BRANCHPARENT:-$BRANCH}

if [ "${BRANCHPARENT}" = "rel/stable" ]; then
    echo "stable"
elif [ "${BRANCHPARENT}" = "rel/beta" ]; then
    echo "beta"
elif [ "${BRANCHPARENT}" = "feature/alphanet" ]; then
    echo "alpha"
else
    echo "dev"
fi
