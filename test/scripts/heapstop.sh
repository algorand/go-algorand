#!/bin/bash
#
# clean up what was started by heapstart.sh

set -e
set -o pipefail
set -x
export SHELLOPTS

if [ -f .heapWatch.pid ]; then
    kill $(cat .heapWatch.pid) || true
fi

if [ -f .pingpong.pid ]; then
    kill $(cat .pingpong.pid) || true
    rm -f .pingpong.pid
fi

TESTDIR=$1
if [ -z "${TESTDIR}" ]; then
    TESTDIR=/tmp/heap_testnetwork
fi

goal network stop -r "${TESTDIR}"

if [ -f .heapWatch.pid ]; then
    kill -9 $(cat .heapWatch.pid) || true
    rm -f .heapWatch.pid
fi
