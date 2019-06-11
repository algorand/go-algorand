#!/usr/bin/env bash

ARCH=$(uname -m)

if [[ "${ARCH}" = "x86_64" ]]; then
    echo "amd64"
elif [[ "${ARCH}" = "armv7l" ]]; then
    echo "arm"
else
    # For now, we're only testing 64-bit (amd64)
    echo "unsupported"
    exit 1
fi
