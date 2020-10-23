#!/usr/bin/env bash

UNAME=$(uname)

if [ "${UNAME}" = "Darwin" ]; then
    echo "darwin"
elif [ "${UNAME}" = "Linux" ]; then
    echo "linux"
elif [[ "${UNAME}" == *"MINGW"* ]] || [[ ${UNAME} == *"MSYS_NT"* ]]; then
    echo "windows"
else
    echo "unsupported"
    exit 1
fi
