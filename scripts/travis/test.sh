#!/usr/bin/env bash

set -e
set -x

if [ "${OS}-${ARCH}" = "linux-arm" ] || [ "${OS}-${ARCH}" = "windows-amd64" ]; then
     # for arm, no tests need to be invoked.
     # for now, disable tests on windows.
     exit 0
 fi

GOPATHBIN=$(go env GOPATH)/bin
export PATH=$PATH:$GOPATHBIN

scripts/travis/run_tests.sh;
scripts/travis/after_build.sh;
