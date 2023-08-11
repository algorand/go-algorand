#!/usr/bin/env bash

# Demonstrate how to run the block-generator runner.

set -e

OUTPUT=../../tmp/OUTPUT_RUN_RUNNER_TEST

CONDUIT_BINARY=$1
if [ -z "$CONDUIT_BINARY" ]; then
  echo "path to conduit binary is required"
  exit 1
fi

POSTGRES_CONTAINER=generator-test-container
POSTGRES_PORT=15432
POSTGRES_DATABASE=generator_db
SCENARIO=${2:-"$(dirname $0)/../test_scenario.yml"}
echo "Using scenario config file: $SCENARIO"

function start_postgres() {
  docker rm -f $POSTGRES_CONTAINER > /dev/null 2>&1 || true

  # Start postgres container...
  docker run \
     -d \
     --name $POSTGRES_CONTAINER \
     -e POSTGRES_USER=algorand \
     -e POSTGRES_PASSWORD=algorand \
     -e PGPASSWORD=algorand \
     -p $POSTGRES_PORT:5432 \
      postgres:13-alpine

   sleep 5

  docker exec -it $POSTGRES_CONTAINER psql -Ualgorand -c "create database $POSTGRES_DATABASE"
}

function shutdown() {
  docker rm -f $POSTGRES_CONTAINER > /dev/null 2>&1 || true
}

trap shutdown EXIT

rm -rf $OUTPUT > /dev/null 2>&1
echo "Building generator."
pushd $(dirname "$0") > /dev/null
go build
popd
echo "Starting postgres container."
start_postgres
echo "Starting test runner"
$(dirname "$0")/block-generator runner \
  --conduit-binary "$CONDUIT_BINARY" \
  --report-directory $OUTPUT \
  --test-duration 30s \
  --conduit-log-level trace \
  --postgres-connection-string "host=localhost user=algorand password=algorand dbname=generator_db port=15432 sslmode=disable" \
  --scenario ${SCENARIO} \
  --reset-db
