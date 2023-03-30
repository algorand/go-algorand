#!/usr/bin/env bash

# Demonstrate how to run the block-generator runner.

set -e

POSTGRES_CONTAINER=generator-test-container
POSTGRES_PORT=15432
POSTGRES_DATABASE=generator_db
CONFIG=${1:-"$(dirname $0)/test_config.yml"}
echo "Using config file: $CONFIG"

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
     postgres

   sleep 5

  docker exec -it $POSTGRES_CONTAINER psql -Ualgorand -c "create database $POSTGRES_DATABASE"
}

function shutdown() {
  docker rm -f $POSTGRES_CONTAINER > /dev/null 2>&1 || true
}

trap shutdown EXIT

rm -rf OUTPUT_RUN_RUNNER_TEST > /dev/null 2>&1
echo "Building generator."
pushd $(dirname "$0") > /dev/null
go build
cd ../.. > /dev/null
echo "Building indexer."
make
popd
echo "Starting postgres container."
start_postgres
echo "Starting test runner"
$(dirname "$0")/block-generator runner \
	--indexer-binary ../algorand-indexer/algorand-indexer \
	--report-directory OUTPUT_RUN_RUNNER_TEST \
	--test-duration 30s \
	--log-level trace \
	--postgres-connection-string "host=localhost user=algorand password=algorand dbname=generator_db port=15432 sslmode=disable" \
	--scenario ${CONFIG}
