#!/usr/bin/env bash

set -ex

# Script to configure or resume a network. Based on environment settings the
# node will be setup with a private network or connect to a public network.

####################
# Helper functions #
####################

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
  configure_data_dir
  start_kmd&

  if [ "$FAST_CATCHUP" ]; then
    catchup&
  fi
  # redirect output to stdout
  algod -o
}

# This should be called on every start to support reconfiguring between runs.
function configure_data_dir() {
  cd "$ALGORAND_DATA"
  algocfg -d . set -p GossipFanout -v 1
  algocfg -d . set -p EndpointAddress -v "0.0.0.0:${ALGOD_PORT}"
  algocfg -d . set -p IncomingConnectionsLimit -v 0
  algocfg -d . set -p Archival -v false
  algocfg -d . set -p IsIndexerActive -v false
  algocfg -d . set -p EnableDeveloperAPI -v true

  # check for config file overrides.
  if [ -f "/etc/config.json" ]; then
    cp /etc/config.json config.json
  fi
  if [ -f "/etc/algod.token" ]; then
    cp /etc/algod.token algod.token
  fi
  if [ -f "/etc/algod.admin.token" ]; then
    cp /etc/algod.admin.token algod.admin.token
  fi

  # check for environment variable overrides.
  if [ "$TOKEN" != "" ]; then
    echo "$TOKEN" > algod.token
  fi
  if [ "$ADMIN_TOKEN" != "" ]; then
    echo "$ADMIN_TOKEN" > algod.admin.token
  fi

  # configure telemetry
  if [ "$TELEMETRY_NAME" != "" ]; then
    diagcfg telemetry name -n "$TELEMETRY_NAME" -d "$ALGORAND_DATA"
    diagcfg telemetry enable -d "$ALGORAND_DATA"
  else
    diagcfg telemetry disable
  fi

  # when using KMD ,install the configuration.
  if [ "$START_KMD" ]; then
    local KMD_DIR="kmd-v0.5"
    # on first start, this directory wont exist.
    mkdir -p "${KMD_DIR}"
    if [ -f "/etc/kmd_config.json" ]; then
      cp /etc/kmd_config.json "${KMD_DIR}"/kmd_config.json
    else
      echo "{{ \"address\":\"0.0.0.0:${KMD_PORT}\",  \"allowed_origins\":[\"*\"] }}" > "${KMD_DIR}"/kmd_config.json
    fi

    if [ "$KMD_TOKEN" != "" ]; then
      echo "$ADMIN_TOKEN" > "${KMD_DIR}"/kmd.token
    fi
  fi
}

# Optionally start KMD service in the background.
function start_kmd() {
  if [ "$START_KMD" ]; then
    kmd start -d "$ALGORNAD_DATA" -t 0
  fi
}

function start_new_public_network() {
  cd /node
  if [ ! -d "run/genesis/$NETWORK" ]; then
    echo "No genesis file for '$NETWORK' is available."
    exit 1
  fi

  mkdir -p "$ALGORAND_DATA"
  mv dataTemplate/* "$ALGORAND_DATA"
  rm -rf dataTemplate

  cp "run/genesis/$NETWORK/genesis.json" "$ALGORAND_DATA/genesis.json"
  cd "$ALGORAND_DATA"

  mv config.json.example config.json

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
  configure_data_dir
  start_kmd&

  # TODO: Is there a way to properly exec a private network?
  goal network start -r "$ALGORAND_DATA/.."
  tail -f "$ALGORAND_DATA/node.log"
}

function start_new_private_network() {
  cd /node
  local TEMPLATE="template.json"
  if [ "$DEV_MODE" ]; then
    TEMPLATE="devmode_template.json"
  fi
  sed -i "s/NUM_ROUNDS/${NUM_ROUNDS:-30000}/" "run/$TEMPLATE"
  goal network create -n dockernet -r "$ALGORAND_DATA/.." -t "run/$TEMPLATE"
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
echo "   TOKEN:         ${TOKEN-:Not Set}"
echo "   KMD_TOKEN:     ${KMD_TOKEN-:Not Set}"
echo "   TELEMETRY_NAME $TELEMETRY_NAME"
echo "   START_KMD"

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
