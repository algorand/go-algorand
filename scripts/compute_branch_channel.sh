#!/usr/bin/env bash

# If enlistment isn't clean, it's 'dev'
./scripts/check_clean_enlistment.sh
if [ $? -ne 0 ]; then
    echo "dev"
    exit 0
fi

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
