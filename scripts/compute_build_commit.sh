#!/bin/bash

# Pi build doesn't support recent enough git with support for --exclude
# COMMIT=$(git describe --always --dirty=+ --exclude="*" 2>&1)

# So use another approach tested to work on both old and new

COMMIT=$(git log -n 1 --pretty="%H")
COMMIT=${COMMIT:0:8}

# Append '+' if it's dirty.
if [[ -n $(git status --porcelain) ]]; then
    COMMIT+="+"
fi

echo ${COMMIT}
