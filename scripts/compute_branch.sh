#!/usr/bin/env bash

if [ -z "${TRAVIS_BRANCH}" ]; then
    BRANCH=$(git rev-parse --abbrev-ref HEAD)
else
    BRANCH="${TRAVIS_BRANCH}"
fi

echo "${BRANCH}"
