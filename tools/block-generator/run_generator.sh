#!/usr/bin/env bash

# Demonstrate how to run the generator and connect it to indexer.

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
  kill -9 $GENERATOR_PID
}

trap shutdown EXIT

echo "Building generator."
pushd $(dirname "$0") > /dev/null
go build
cd ../.. > /dev/null
echo "Building indexer."
make
popd
echo "Starting postgres container."
start_postgres
echo "Starting block generator (see generator.log)"
$(dirname "$0")/block-generator daemon --port 11111 --config "${CONFIG}" &
GENERATOR_PID=$!
echo "Starting indexer"
$(dirname "$0")/../../cmd/algorand-indexer/algorand-indexer daemon \
              -S localhost:8980 \
              --algod-net localhost:11111 \
              --algod-token security-is-our-number-one-priority \
              --metrics-mode VERBOSE \
              -P "host=localhost user=algorand password=algorand dbname=generator_db port=15432 sslmode=disable"
