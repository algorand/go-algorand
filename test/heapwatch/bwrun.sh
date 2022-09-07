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

netgoal generate --nodes 8 --relays 3 -r "${TESTROOT}" -o "${TESTROOT}"/netgoal_a.json --template goalnet -w 15
jq .Genesis.LastPartKeyRound=5000 < "${TESTROOT}"/netgoal_a.json > "${TESTROOT}"/netgoal.json

TESTDIR="${TESTROOT}"/net

REPO_ROOT="$( cd "$(dirname "$0")" ; pwd -P )"/../..

goal network create -r "${TESTDIR}" -t "${TESTROOT}"/netgoal.json -n r3n8

goal network start -r "${TESTDIR}"

# give all the algod a moment...
sleep 2

# TODO: other pingpong modes
pingpong run -d "${TESTDIR}/node1" --tps 20 --refresh 9999 --quiet &

echo "$!" > .pingpong1.pid

pingpong run -d "${TESTDIR}/node2" --tps 20 --refresh 9999 --quiet &

echo "$!" > .pingpong2.pid

mkdir -p "${TESTDIR}/heaps"
#python3 "${REPO_ROOT}/test/heapwatch/heapWatch.py" -o "${TESTDIR}/heaps" --no-heap --metrics --blockinfo --period 90 "${TESTDIR}"/{node,relay}* --runtime 910 > "${TESTDIR}/heaps/watch.log" 2>&1
python3 "${REPO_ROOT}/test/heapwatch/heapWatch.py" -o "${TESTDIR}/heaps" --metrics --blockinfo --period 90 "${TESTDIR}"/{node,relay}* --runtime 9100 > "${TESTDIR}/heaps/watch.log" 2>&1

for i in .pingpong*.pid; do
    kill $(cat $i) || true
    rm -f "${i}"
done

goal network stop -r "${TESTDIR}"

python3 "${REPO_ROOT}/test/heapwatch/metrics_delta.py" '--nick-lre=relay:relay\d+|Primary\d*' '--nick-lre=pn:[nN]ode\d+' -d "${TESTDIR}/heaps" > "${TESTDIR}/heaps/report"
python3 "${REPO_ROOT}/test/heapwatch/client_ram_report.py" --csv "${TESTDIR}/heaps/crr.csv" -d "${TESTDIR}/heaps"
python3 "${REPO_ROOT}/test/heapwatch/plot_crr_csv.py" "${TESTDIR}/heaps/crr.csv"
cat "${TESTDIR}/heaps/report"
