#!/usr/bin/env bash

set -e

if [[ $# -ne 1 ]]; then
    echo syntax: find-nodes parent-data-dir
    exit 1
fi

ALLDIRS=""

for DD in $1/*/
do
    if [ -f ${DD}/genesis.json ]; then
        ALLDIRS="${ALLDIRS} -d ${DD}"
    fi
done

echo ${ALLDIRS}
