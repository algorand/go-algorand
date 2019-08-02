#!/usr/bin/env bash

CHANNEL="$1"
if [ -z "${CHANNEL}" ]; then
    echo "Specify a channel name to convert to an install channel"
    exit 1
fi

if [ "${CHANNEL}" = "stable" ]; then
    echo "stable"
elif [ "${CHANNEL}" = "beta" ]; then
    echo "beta"
else
    echo "nightly"
fi
