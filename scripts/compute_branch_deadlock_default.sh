#!/usr/bin/env bash

# if the user ( i.e. algorand developer ) has explicitly enabled the deadlock detection in his environment, we want to enable it.
if [ "$ALGORAND_DEADLOCK" != "" ]; then
    echo "$ALGORAND_DEADLOCK"
    exit 0
fi

# we used to disable the deadlock on all release builds, which cause issues with individuals who compiled it on their own.
# as a result, we decided to disable it always, unless we're running on travis. If we'll ever want to make it dependent
# on the build branch, the build branch is available in $1. ( i.e. if [[ "$1" =~ ^rel/ ]]; then ... )
echo "disable"
