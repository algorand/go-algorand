#!/usr/bin/env bash

# When a Jenkins job watches multiple branches, the GIT_BRANCH env var can return "origin/rel/beta"
# and the remote repo name must be # stripped from the front of the string.

BRANCH="$1"

for repo in $(git remote)
do
    pattern="$repo"/

    if [[ "$BRANCH" =~ ^$pattern ]]
    then
        # Remove matching prefix.
        echo "${BRANCH#$pattern}"
        exit 0
    fi
done

echo "$BRANCH"

