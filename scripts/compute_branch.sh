#!/usr/bin/env bash

if [[ -n $(git status --porcelain) ]]; then
    # If the branch isn't clean, default to HEAD to match old behavior.
    BRANCH="HEAD"
elif [ -z "${TRAVIS_BRANCH}" ]; then
    # if there is no travis branch, set based on tag or branch
    case "$(git describe --tags)" in
      *"beta")    BRANCH="rel/beta" ;;
      *"stable")  BRANCH="rel/stable" ;;
      *"nightly") BRANCH="rel/nightly" ;;
      *)          BRANCH=$(git rev-parse --abbrev-ref HEAD)
    esac
else
    BRANCH="${TRAVIS_BRANCH}"
fi

echo "${BRANCH}"
