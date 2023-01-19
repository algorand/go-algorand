#!/usr/bin/env bash

set -ex

# Script to configure or resume a network. Based on environment settings the
# node will be setup with a private network or connect to a public network.

####################
# Helper functions #
####################

function apply_configuration() {
  cd "$ALGORAND_DATA"

  # check for config file overrides.
  if [ -f "/etc/algorand/config.json" ]; then
    cp /etc/algorand/config.json config.json
  fi
  if [ -f "/etc/algorand/algod.token" ]; then
    cp /etc/algorand/algod.token algod.token
  fi
  if [ -f "/etc/algorand/algod.admin.token" ]; then
    cp /etc/algorand/algod.admin.token algod.admin.token
  fi
  if [ -f "/etc/algorand/logging.config" ]; then
    cp /etc/algorand/logging.config logging.config
  fi

  # check for environment variable overrides.
  if [ "$TOKEN" != "" ]; then
    echo "$TOKEN" >algod.token
  fi
  if [ "$ADMIN_TOKEN" != "" ]; then
    echo "$ADMIN_TOKEN" >algod.admin.token
  fi

  # configure telemetry
  if [ "$TELEMETRY_NAME" != "" ]; then
    diagcfg telemetry name -n "$TELEMETRY_NAME" -d "$ALGORAND_DATA"
    diagcfg telemetry enable -d "$ALGORAND_DATA"
  else
    diagcfg telemetry disable
  fi
}

function catchup() {
  local FAST_CATCHUP_URL="https://algorand-catchpoints.s3.us-east-2.amazonaws.com/channel/CHANNEL/latest.catchpoint"
  local CATCHPOINT=$(curl -s ${FAST_CATCHUP_URL/CHANNEL/$NETWORK})
  if [[ "$(echo $CATCHPOINT | wc -l | tr -d ' ')" != "1" ]]; then
    echo "Problem starting fast catchup."
    exit 1
  fi

  sleep 5
  goal node catchup "$CATCHPOINT"
}

function start_public_network() {
  cd "$ALGORAND_DATA"

  apply_configuration

  if [[ $FAST_CATCHUP ]]; then
    catchup &
  fi
  # redirect output to stdout
  algod -o
}

function configure_data_dir() {
  cd "$ALGORAND_DATA"
  algocfg -d . set -p GossipFanout -v 1
  algocfg -d . set -p EndpointAddress -v "0.0.0.0:${ALGOD_PORT}"
  algocfg -d . set -p IncomingConnectionsLimit -v 0
  algocfg -d . set -p Archival -v false
  algocfg -d . set -p IsIndexerActive -v false
  algocfg -d . set -p EnableDeveloperAPI -v true
}

function start_new_public_network() {
  cd /algod
  if [ ! -d "/node/run/genesis/${NETWORK}" ]; then
    echo "No genesis file for '$NETWORK' is available."
    exit 1
  fi

  mkdir -p "$ALGORAND_DATA"

  cd "$ALGORAND_DATA"

  cp "/node/run/genesis/${NETWORK}/genesis.json" genesis.json
  cp /node/run/config.json.example config.json

  configure_data_dir

  local ID
  case $NETWORK in
    mainnet)  ID="<network>.algorand.network";;
    testnet)  ID="<network>.algorand.network";;
    betanet)  ID="<network>.algodev.network";;
    alphanet) ID="<network>.algodev.network";;
    devnet)   ID="<network>.algodev.network";;
    *)        echo "Unknown network"; exit 1;;
  esac
  set -p DNSBootstrapID -v "$ID"

  start_public_network
}

function start_private_network() {
  apply_configuration

  # TODO: Is there a way to properly exec a private network?
  goal network start -r "${ALGORAND_DATA}/.."
  tail -f "${ALGORAND_DATA}/node.log"
}

function start_new_private_network() {
  local TEMPLATE="template.json"
  if [ "$DEV_MODE" ]; then
    TEMPLATE="devmode_template.json"
  fi
  sed -i "s/NUM_ROUNDS/${NUM_ROUNDS:-30000}/" "/node/run/$TEMPLATE"
  goal network create --noclean -n dockernet -r "${ALGORAND_DATA}/.." -t "/node/run/$TEMPLATE"
  configure_data_dir
  start_private_network
}

##############
# Entrypoint #
##############

echo "Starting Algod Docker Container"
echo "   ALGORAND_DATA: $ALGORAND_DATA"
echo "   NETWORK:       $NETWORK"
echo "   ALGOD_PORT:    $ALGOD_PORT"
echo "   FAST_CATCHUP:  $FAST_CATCHUP"
echo "   DEV_MODE:      $DEV_MODE"
echo "   TOKEN:         $TOKEN"
echo "   TELEMETRY_NAME $TELEMETRY_NAME"

# If data directory is initialized, start existing environment.
if [ -f "$ALGORAND_DATA/../network.json" ]; then
  start_private_network
  exit 1
elif [ -f "$ALGORAND_DATA/genesis.json" ]; then
  start_public_network
  exit 1
fi

# Initialize and start network.
if [ "$NETWORK" == "" ]; then
  start_new_private_network
else
  start_new_public_network
fi
