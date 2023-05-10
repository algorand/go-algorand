#!/usr/bin/env bash

# Demonstrate how to run the block-generator runner.

set -e

CONDUIT_BINARY=$1
if [ -z "$CONDUIT_BINARY" ]; then
  echo "path to conduit binary is required"
  exit 1
fi

POSTGRES_CONTAINER=generator-test-container
POSTGRES_PORT=15432
POSTGRES_DATABASE=generator_db
CONFIG=${3:-"$(dirname $0)/test_config.yml"}
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
popd
echo "Starting test runner"
$(dirname "$0")/block-generator runner \
	--conduit-binary "$CONDUIT_BINARY" \
	--report-directory OUTPUT_RUN_RUNNER_TEST \
	--test-duration 30s \
	--log-level trace \
	--postgres-connection-string "host=localhost user=algorand password=algorand dbname=indexer_db port=45432 sslmode=disable" \
	--scenario ${CONFIG} \
	--db-round ${2:-0} \
	--genesis-file ../../tmp/genesis.json \
	-k
