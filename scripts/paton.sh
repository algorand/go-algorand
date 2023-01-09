#!/usr/bin/env bash

set -euxf -o pipefail

# Primarily intended for continuous benchmarking, paton.sh judges benchmark
# performance across 2 git commits against a user-provided percent threshold.
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
# * https://pypi.org/project/tabulate

if [[ $# -lt 1 ]]; then
  echo "Must provide required flags"
  exit 1
fi

MODE="all"

# Argument parsing crafted with help from https://stackoverflow.com/a/14203146.
while [[ $# -gt 0 ]]; do
  case $1 in
    -m|--mode)
      MODE="$2"
      shift # past argument
      shift # past value
      ;;
    -c|--test-cmd)
      GO_TEST_CMD=("$2")
      shift # past argument
      shift # past value
      ;;
    -a|--alert-threshold-pct)
      ALERT_THRESHOLD_PCT="$2"
      shift # past argument
      shift # past value
      ;;
    -r|--git-repo)
      GIT_REPO="$2"
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

function run_benchmark {
  COMPARE_COMMIT=$(git rev-parse "$COMPARE")

  git -c advice.detachedHead=false checkout "$BASE"
  go test ${GO_TEST_CMD[*]} | tee /tmp/base.txt

  git -c advice.detachedHead=false checkout "$COMPARE_COMMIT"
  go test ${GO_TEST_CMD[*]} | tee /tmp/compare.txt

  benchstat -delta-test none /tmp/base.txt /tmp/compare.txt | tee /tmp/benchstat.txt
}

function commit_url {
  local ref="$1"

  local sha="$(git rev-parse $ref)"
  echo "https://github.com/${GIT_REPO}/commit/${sha}"
}

function evaluate_benchmark {
  cat /tmp/benchstat.txt |
    awk -F ' {2,}' 'NR==1 || sub(/\+/, "")' | # Preserve header and enable numeric comparison by removing leading '+' sign.
    awk -v threshold="$ALERT_THRESHOLD_PCT" -F ' {2,}' '$4 > threshold { print }' |
    tabulate --format github --header --sep '[\s]{2,}' > /tmp/benchstat-degradations.md

  if [ "$(wc -l /tmp/benchstat-degradations.md | awk '{print $1}')" -gt 2 ]; then
    echo "# :warning: Benchmark performance degradation detected" > /tmp/failures.md
    echo "* [old]($(commit_url $BASE))" >> /tmp/failures.md
    echo "* [new]($(commit_url $COMPARE))" >> /tmp/failures.md
    echo "" >> /tmp/failures.md
    cat /tmp/benchstat-degradations.md >> /tmp/failures.md
    cat /tmp/failures.md
  fi
}

if [[ "$MODE" == "all" || "$MODE" == "benchmark" ]]; then
  run_benchmark
fi

if [[ "$MODE" == "all" || "$MODE" == "evaluate" ]]; then
  evaluate_benchmark
fi