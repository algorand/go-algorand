#!/bin/bash
#
# clean up what was started by start.sh or bwstart.sh

set -e
set -o pipefail
set -x
export SHELLOPTS

if [ -f .heapWatch.pid ]; then
    kill $(cat .heapWatch.pid) || true
fi

for i in .pingpong*.pid; do
    kill $(cat $i) || true
    rm -f "${i}"
done

TESTDIR=$1
if [ -z "${TESTDIR}" ]; then
    TESTDIR=/tmp/heap_testnetwork
fi
if [ -d "${TESTDIR}/net" ]; then
    # started with bwstart.sh
    TESTDIR="${TESTDIR}/net"
fi

goal network stop -r "${TESTDIR}"

if [ -f .heapWatch.pid ]; then
    kill -9 $(cat .heapWatch.pid) || true
    rm -f .heapWatch.pid
fi
