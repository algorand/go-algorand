#!/bin/bash
#
# Run a local 3-relay 8-leaf-node test.
# Run 40 TPS of payment txns through it.
# Record metrics for bandwidth analysis.

set -e
set -o pipefail
set -x
export SHELLOPTS

TESTROOT=$1
if [ -z "${TESTROOT}" ]; then
    TESTROOT=/tmp/heap_testnetwork
fi

mkdir -p "${TESTROOT}"

netgoal generate --nodes 8 --relays 3 -r "${TESTROOT}" -o "${TESTROOT}"/netgoal.json --template goalnet -w 15

TESTDIR="${TESTROOT}"/net

REPO_ROOT="$( cd "$(dirname "$0")" ; pwd -P )"/../..

goal network create -r "${TESTDIR}" -t "${TESTROOT}"/netgoal.json -n r3n8

goal network start -r "${TESTDIR}"

# give all the algod a moment...
sleep 2

mkdir -p "${TESTDIR}/heaps"
python3 "${REPO_ROOT}/test/heapwatch/heapWatch.py" -o "${TESTDIR}/heaps" --no-heap --metrics --blockinfo --period 90 "${TESTDIR}"/{node,relay}* &

echo "$!" > .heapWatch.pid

# TODO: other pingpong modes
pingpong run -d "${TESTDIR}/node1" --tps 20 --rest 0 --run 0 &

echo "$!" > .pingpong1.pid

pingpong run -d "${TESTDIR}/node2" --tps 20 --rest 0 --run 0 &

echo "$!" > .pingpong2.pid
