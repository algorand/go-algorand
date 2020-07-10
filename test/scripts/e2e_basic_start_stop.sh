#!/usr/bin/env bash
echo "######################################################################"
echo "  e2e_basic_start_stop"
echo "######################################################################"
set -e

# Suppress telemetry reporting for tests
export ALGOTEST=1

RUNNING_COUNT=0

function update_running_count() {
    PIDS=($(pgrep -u $(whoami) -x algod)) || true
    RUNNING_COUNT=${#PIDS[@]}
}

function verify_at_least_one_running() {
    # Starting up can take some time, so wait at least 2 seconds
    for TRIES in 1 2 3 4 5; do
        update_running_count
        if [ ${RUNNING_COUNT} -ge 1 ]; then
            return 0
        fi
        sleep .4
    done
    echo "at least one algod expected to be running but ${RUNNING_COUNT} are running"
    exit 1
}

function verify_none_running() {
    # Shutting down can take some time, so wait at least 5 seconds
    for TRIES in 1 2 3 4 5; do
        update_running_count
        if [ ${RUNNING_COUNT} -eq 0 ]; then
            return 0
        fi
        sleep 1.4
    done
    echo "algod not expected to be running but it is"
    exit 1
}

function verify_one_running() {
    # Starting up can take some time, so retry up to 2 seconds
    for TRIES in 1 2 3 4 5; do
        update_running_count
        if [ ${RUNNING_COUNT} -eq 1 ]; then
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
goal node start -d ${DATADIR}
verify_at_least_one_running

echo Verifying we can stop it using goal
goal node stop -d ${DATADIR}
verify_none_running

#----------------------
# Test that we can start a generic node straight with no overrides
echo Verifying a generic node will start directly
algod -d ${DATADIR} &
verify_at_least_one_running
pkill -u $(whoami) -x algod || true
verify_none_running

#----------------------
# Test that we can start a generic node against the datadir
# but that we cannot start a second one against same datadir
echo Verifying that the datadir algod lock works correctly
algod -d ${DATADIR} &
verify_at_least_one_running
algod -d ${DATADIR} &
verify_at_least_one_running # one should still be running
verify_one_running # in fact, exactly one should still be running
# clean up
pkill -u $(whoami) -x algod || true
verify_none_running

echo "----------------------------------------------------------------------"
echo "  DONE: e2e_basic_start_stop"
echo "----------------------------------------------------------------------"
