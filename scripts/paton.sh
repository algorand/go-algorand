#!/usr/bin/env bash

set -euxf -o pipefail

# Primarily intended for continuous benchmarking, paton.sh compares Go
# benchmarks between 2 git commits and outputs the comparison in a format
# compatible with https://github.com/benchmark-action/github-action-benchmark.
#
# paton.sh is inspired by https://github.com/knqyf263/cob.  cob minimizes
# benchmarking variance by running provided benchmarks against 2 commits in 1
# invocation rather than comparing against a previously stored result.
# Comparing against a previously stored result requires a stable benchmark
# environment across time.  Particularly in fully managed CI environments, a
# stable benchmark environment cannot be guaranteed.
#
# paton.sh's namesake is https://en.wikipedia.org/wiki/Paton_Bridge.
#
# paton.sh requires these dependencies.  No attempt is made to install prerequisites:
# * https://pkg.go.dev/golang.org/x/perf/cmd/benchstat
# * https://github.com/stedolan/jq
# * https://github.com/kellyjonbrazil/jc

if [[ $# -lt 1 ]]; then
  echo "Must provide required flags"
  exit 1
fi

# Argument parsing crafted with help from https://stackoverflow.com/a/14203146.
while [[ $# -gt 0 ]]; do
  case $1 in
    -c|--test-cmd)
      GO_TEST_CMD=("$2")
      shift # past argument
      shift # past value
      ;;
    *)
      echo "Unknown flag"
      exit 1
      ;;
  esac
done

BASE="HEAD~1"
COMPARE="HEAD"

COMPARE_COMMIT=$(git rev-parse "$COMPARE")

git -c advice.detachedHead=false checkout "$BASE"
go test ${GO_TEST_CMD[*]} | tee /tmp/base.txt

git -c advice.detachedHead=false checkout "$COMPARE_COMMIT"
go test ${GO_TEST_CMD[*]} | tee /tmp/compare.txt

benchstat -delta-test none /tmp/base.txt /tmp/compare.txt | tee /tmp/benchstat.txt

cat /tmp/benchstat.txt |
  awk '/old time\/op/{f=1} /^$/{f=0} f' |
  jc -p --asciitable |
  # Remove symbols (+, %) preventing conversion to JavaScript number.
  sed '/delta/s/+//g' |
  sed '/delta/s/%//g' |
  tee /tmp/benchstat_time.json

cat /tmp/benchstat_time.json |
  jq '.[] | {
    name: (.name + "-"),
    value: .delta | tonumber,
    unit: "Percent"
    }' |
  jq -s > /tmp/benchstat_time_jq.json
