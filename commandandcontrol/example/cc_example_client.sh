#!/usr/bin/env bash
set -v
set -x

CC_SERVICE_HOST=localhost:9080
SLEEP_TIME=10

# Start ping pong running on all known host and instances with configuration from pingpong1.json
cc_client \
    -service-addr ${CC_SERVICE_HOST} \
    -target *:* \
    -component pingpong \
    -action start \
    -options ./pingpong1.json

# Sleep 
sleep ${SLEEP_TIME}

# Restart ping pong running on all host Host1 and node Primary with configuration from pingpong2.json
cc_client \
    -service-addr ${CC_SERVICE_HOST} \
    -target Host1:Primary \
    -component pingpong \
    -action start \
    -options ./pingpong2.json

# Sleep 
sleep ${SLEEP_TIME}

# Stop ping pong on all known instances and nodes
cc_client \
    -service-addr ${CC_SERVICE_HOST} \
    -target *:* \
    -component pingpong \
    -action stop \
    -options ./pingpong1.json
