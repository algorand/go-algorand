#!/usr/bin/env bash

UNAME=$(uname)

if [ "${UNAME}" = "Darwin" ]; then
    echo "darwin"
elif [ "${UNAME}" = "Linux" ]; then
    echo "linux"
else
    echo "unsupported"
    exit 1
fi
