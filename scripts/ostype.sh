#!/usr/bin/env bash

if [ ! -z "${GOHOSTOS+x}" ]; then
    echo "${GOHOSTOS}"
    exit 0
fi

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
