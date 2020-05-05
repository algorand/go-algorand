#!/usr/bin/env bash
# shellcheck disable=1090

set -ex

export WORKDIR="$1"
export OS_TYPE="$2"
export ARCH_TYPE="$3"
export ARCH_BIT="$4"
export FULLVERSION="$5"

if [ -z "$WORKDIR" ]
then
    echo "WORKDIR must be defined."
    exit 1
fi

. "$WORKDIR/scripts/release/mule/test/util/setup.sh" rpm

