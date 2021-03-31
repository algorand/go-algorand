#!/bin/bash

set -e
set -o pipefail
set -x
export SHELLOPTS

TESTDIR=$1
if [ -z "${TESTDIR}" ]; then
    TESTDIR=/tmp/heap_testnetwork
fi

REPO_ROOT="$( cd "$(dirname "$0")" ; pwd -P )"/../..

goal network create -r "${TESTDIR}" -t "${REPO_ROOT}/test/testdata/nettemplates/ThreeNodesEvenDist.json" -n tbd

goal network start -r "${TESTDIR}"

# give all the algod a moment...
sleep 2

mkdir -p "${TESTDIR}/heaps"
python3 "${REPO_ROOT}/test/scripts/heapWatch.py" -o "${TESTDIR}/heaps" --period 10m "${TESTDIR}/"* &

echo "$!" > .heapWatch.pid

pingpong run -d "${TESTDIR}/Node1" --tps 10 --rest 0 --run 0 --nftasapersecond 200 &

echo "$!" > .pingpong1.pid

pingpong run -d "${TESTDIR}/Node2" --tps 10 --rest 0 --run 0 --nftasapersecond 200 &

echo "$!" > .pingpong2.pid
