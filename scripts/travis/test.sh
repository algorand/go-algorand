#!/usr/bin/env bash

set -e

SCRIPTPATH="$( cd "$(dirname "$0")" ; pwd -P )"
OS=$("${SCRIPTPATH}/../ostype.sh")
ARCH=$("${SCRIPTPATH}/../archtype.sh")

if [ "${OS}-${ARCH}" = "linux-arm" ]; then
    # for arm, no tests need to be invoked.
    exit 0
fi

make fixcheck
if [[ "${OS}" != "darwin" ]]; then scripts/travis/run_tests.sh; fi
if [[ "${OS}" != "darwin" ]]; then scripts/travis/after_build.sh; fi
