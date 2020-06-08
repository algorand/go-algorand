#!/usr/bin/env bash

# ./compute_package_name <CHANNEL>

if [ "$1" = "nightly" ]; then
    echo "algorand-nightly"
elif [ "$1" = "beta" ]; then
    echo "algorand-beta"
else
    echo "algorand"
fi

