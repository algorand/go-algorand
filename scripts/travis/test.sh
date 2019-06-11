#!/usr/bin/env bash

set -e

make fixcheck
if [[ "$TRAVIS_OS_NAME" != "osx" ]]; then scripts/travis/run_tests.sh; fi
if [[ "$TRAVIS_OS_NAME" != "osx" ]]; then scripts/travis/after_build.sh; fi
