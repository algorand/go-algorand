#!/usr/bin/env bash
echo "######################################################################"
echo "  run_integration_tests"
echo "######################################################################"
set -e

# Suppress telemetry reporting for tests
export ALGOTEST=1

# Run more comprehensive tests (not just 'go test' tests)
CHANNEL=$(./scripts/travis/channel_for_branch.sh)
#./test/scripts/test_running_install_and_update.sh -c "${CHANNEL}"
#./test/scripts/test_update_rollback.sh -c "${CHANNEL}"

# Test deploying, running, and deleting a local private network
./test/scripts/test_private_network.sh

# Run suite of e2e tests against a single installation of the current build
./test/scripts/e2e.sh

echo "----------------------------------------------------------------------"
echo "  DONE: run_integration_tests"
echo "----------------------------------------------------------------------"
