#!/usr/bin/env bash

set -euf -o pipefail

echo "######################################################################"
echo "  e2e_basic_start_stop"
echo "######################################################################"

if [ "$#" -eq 0 ]; then
  echo "Usage: e2e_basic_start_stop.sh <DATA_DIR>"
  exit 1
fi

DATA_DIR="$1"
RUNNING_COUNT=0
# Suppress telemetry reporting for tests
export ALGOTEST=1

function update_running_count() {
    PIDS=($(pgrep -u "$(whoami)" -x algod)) || true
    RUNNING_COUNT=${#PIDS[@]}
}

function verify_at_least_one_running() {
    # Starting up can take some time, so wait at least 2 seconds
    for _ in 1 2 3 4 5; do
        update_running_count
        if [ "$RUNNING_COUNT" -ge 1 ]; then
            return 0
        fi
        sleep .4
    done
    echo "at least one algod expected to be running but ${RUNNING_COUNT} are running"
    exit 1
}

function verify_none_running() {
    # Shutting down can take some time, so wait at least 5 seconds
    for _ in 1 2 3 4 5; do
        update_running_count
        if [ "$RUNNING_COUNT" -eq 0 ]; then
            return 0
        fi
        sleep 1.4
    done
    echo "algod not expected to be running but it is"
    if [ -n "$DATA_DIR" ]; then
        echo "last 20 lines of node.log:"
        tail -20 "$DATA_DIR/node.log"
        echo "================================"
        echo "stdout and stdin:"
        cat "$DATA_DIR/algod-out.log"
        echo "================================"
        cat "$DATA_DIR/algod-err.log"
    fi
    exit 1
}

function verify_one_running() {
    # Starting up can take some time, so retry up to 2 seconds
    for _ in 1 2 3 4 5; do
        update_running_count
        if [ "$RUNNING_COUNT" -eq 1 ]; then
            return 0
        fi
        sleep .4
    done
    echo "only one algod expected to be running but ${RUNNING_COUNT} are running"
    exit 1
}

# No nodes should be running when we start
verify_none_running

#----------------------
# Test that we can start & stop a generic node with no overrides
echo Verifying a generic node will start using goal
goal node start -d "$DATA_DIR"
verify_at_least_one_running

echo Verifying we can stop it using goal
goal node stop -d "$DATA_DIR"
verify_none_running

#----------------------
# Test that we can start a generic node straight with no overrides
echo Verifying a generic node will start directly
algod -d "$DATA_DIR" &
verify_at_least_one_running
pkill -u "$(whoami)" -x algod || true
verify_none_running

#----------------------
# Test that we can start a generic node against the data dir
# but that we cannot start a second one against same data dir
echo Verifying that the data dir algod lock works correctly
algod -d "$DATA_DIR" &
verify_at_least_one_running
algod -d "$DATA_DIR" &
verify_at_least_one_running # one should still be running
verify_one_running # in fact, exactly one should still be running
# clean up
pkill -u "$(whoami)" -x algod || true
verify_none_running

echo "----------------------------------------------------------------------"
echo "  DONE: e2e_basic_start_stop"
echo "----------------------------------------------------------------------"
