#!/usr/bin/env bash

# integration_test.sh - Performs pre-build checks on the branch
#
# Syntax:   integration_test.sh
#
# Usage:    Should only be used by Travis
#
# Examples: scripts/travis/integration_test.sh

./scripts/travis/build.sh || travis_terminate 1;
travis_wait 90 ./scripts/travis/test.sh