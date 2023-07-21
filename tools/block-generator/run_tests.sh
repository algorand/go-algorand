#!/usr/bin/env bash

CONNECTION_STRING=""
CONDUIT_BINARY=""
REPORT_DIR=""
DURATION="1h"
LOG_LEVEL="error"
SCENARIOS=""

help() {
  echo "Usage:"
  echo " -v|--verbose    enable verbose script output."
  echo " -c|--connection-string"
  echo "                 PostgreSQL connection string."
  echo " -i|--conduit    path to conduit binary."
  echo " -s|--scenarios  path to conduit test scenarios."
  echo " -r|--report-dir directory where the report should be written."
  echo " -d|--duration   test duration."
  echo " -l|--level      log level to pass to conduit."
  echo " -g|--generator  block-generator binary to run the generator."
  exit
}

while :; do
  case "${1-}" in
  -h | --help) help ;;
  -v | --verbose) set -x ;;
  -c | --connection-string)
    CONNECTION_STRING="${2-}"
    shift
    ;;
  -g | --generator)
    GENERATOR_BINARY="${2-}"
    shift
    ;;
  -i | --conduit)
    CONDUIT_BINARY="${2-}"
    shift
    ;;
  -r | --report-dir)
    REPORT_DIR="${2-}"
    shift
    ;;
  -s | --scenarios)
    SCENARIOS="${2-}"
    shift
    ;;
  -d | --duration)
    DURATION="${2-}"
    shift
    ;;
  -l | --level)
    LOG_LEVEL="${2-}"
    shift
    ;;
  -?*) echo "Unknown option: $1" && exit 1;;
  *) break ;;
  esac
  shift
done

args=("$@")

if [ -z "$CONNECTION_STRING" ]; then
  echo "Missing required connection string parameter (-c / --connection-string)."
  exit 1
fi

if [ -z "$CONDUIT_BINARY" ]; then
  echo "Missing required conduit binary parameter (-i / --conduit)."
  exit 1
fi

if [ -z "$SCENARIOS" ]; then
  echo "Missing required conduit test scenario parameter (-s / --scenarios)."
  exit 1
fi

if [ -z "$GENERATOR_BINARY" ]; then
  echo "path to block-generator binary is required"
  exit 1
fi

echo "Running with binary: $CONDUIT_BINARY"
echo "Report directory: $REPORT_DIR"
echo "Duration: $DURATION"
echo "Log Level: $LOG_LEVEL"

"$GENERATOR_BINARY" runner \
  -i "$CONDUIT_BINARY" \
  -s "$SCENARIOS" \
  -d "$DURATION" \
  -c "$CONNECTION_STRING" \
  --report-directory "$REPORT_DIR" \
  --conduit-log-level "$LOG_LEVEL" \
  --reset-report-dir

