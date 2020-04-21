#!/usr/bin/env bash

# If enlistment isn't clean, it's 'dev'
CWD=$(cd "$(dirname "$0")" && pwd -P)

if [ "$1" = "master" ]; then
    echo "master"
elif [ "$1" = "rel/nightly" ]; then
    echo "nightly"
elif [ "$1" = "rel/stable" ]; then
    echo "stable"
elif [ "$1" = "rel/beta" ]; then
    echo "beta"
else
    echo "dev"
fi

