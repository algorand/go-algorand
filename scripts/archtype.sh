#!/usr/bin/env bash

ARCH=$(uname -m)

if [[ "${ARCH}" = "x86_64" ]]; then
    echo "amd64"
elif [[ "${ARCH}" = "armv6l" ]]; then
    echo "arm"
elif [[ "${ARCH}" = "armv7l" ]]; then
    echo "arm"
elif [[ "${ARCH}" = "aarch64" ]] || [[ "${ARCH}" = "arm64" ]]; then
    echo "arm64"
else
    # Anything else needs to be specifically added...
    echo "unsupported"
    exit 1
fi
