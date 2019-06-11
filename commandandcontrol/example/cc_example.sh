#!/usr/bin/env bash
set -v
set -x

CC_SERVICE_HOST="localhost:9080"
BIN_DIR=${GOPATH}/bin/
TEMP_DIR=${TMPDIR}
SLEEP_TIME=5

# Start the cc_service
cc_service \
    -addr ${CC_SERVICE_HOST} &

sleep ${SLEEP_TIME}

# Start the cc_agent for 2 local algod instances
cc_agent \
    -service-addr ${CC_SERVICE_HOST} \
    -hostname Host1 \
    -bindir ${BIN_DIR} \
    -tempdir ${TEMP_DIR} \
    -d /tmp/test3/root/Node \
    -d /tmp/test3/root/Primary/ &
