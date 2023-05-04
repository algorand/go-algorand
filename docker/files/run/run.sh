#!/usr/bin/env bash

set -e

if [ "$DEBUG" = "1" ]; then
  set -x
fi

# To allow mounting the data directory we need to change permissions
# to our algorand user. The script is initially run as the root user
# in order to change permissions, afterwards the script is re-launched
# as the algorand user.
if [ "$(id -u)" = '0' ]; then
  chown -R algorand:algorand $ALGORAND_DATA
  exec runuser -u algorand "$BASH_SOURCE"
fi

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
  cd "$ALGORAND_DATA"

  configure_data_dir
  start_kmd &

  if [ "$FAST_CATCHUP" = "1" ]; then
    catchup &
  fi

  if [ "$PEER_ADDRESS" != "" ]; then
       printf "$PEER_ADDRESS"
       algod -o -p $PEER_ADDRESS
  else
    # redirect output to stdout
    algod -o
  fi
}

function configure_data_dir() {
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

  # initialize config with profile.
  if [ "$PROFILE" != "" ]; then
    algocfg profile set --yes -d "$ALGORAND_DATA" "$PROFILE" 
  fi

  # call after copying config.json to make sure the port is exposed.
  algocfg -d . set -p EndpointAddress -v "0.0.0.0:${ALGOD_PORT}"

  # check for token overrides
  if [ "$TOKEN" != "" ]; then
    for dir in ${ALGORAND_DATA}/../*/; do
      echo "$TOKEN" > "$dir/algod.token"
    done
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

  # start kmd
  if [ "$START_KMD" = "1" ]; then
    local KMD_DIR="kmd-v0.5"
    # on intial bootstrap, this directory won't exist.
    mkdir -p "$KMD_DIR"
    chmod 0700 "$KMD_DIR"
    cd "$KMD_DIR"
    if [ -f "/etc/algorand/kmd_config.json" ]; then
      cp /etc/algorand/kmd_config.json kmd_config.json
    else
      echo "{ \"address\":\"0.0.0.0:${KMD_PORT}\", \"allowed_origins\":[\"*\"] }" >kmd_config.json
    fi

    if [ "$KMD_TOKEN" != "" ]; then
      echo "$KMD_TOKEN" >kmd.token
    fi
  fi
}

function start_kmd() {
  if [ "$START_KMD" = "1" ]; then
    goal kmd start -d "$ALGORAND_DATA"
  fi
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
  mainnet) ID="<network>.algorand.network" ;;
  testnet) ID="<network>.algorand.network" ;;
  betanet) ID="<network>.algodev.network" ;;
  alphanet) ID="<network>.algodev.network" ;;
  devnet) ID="<network>.algodev.network" ;;
  *)
    echo "Unknown network"
    exit 1
    ;;
  esac
  set -p DNSBootstrapID -v "$ID"

  start_public_network
}

function start_private_network() {
  configure_data_dir
  start_kmd

  # TODO: Is there a way to properly exec a private network?
  goal network start -r "${ALGORAND_DATA}/.."
  tail -f "${ALGORAND_DATA}/node.log"
}

function start_new_private_network() {
  local TEMPLATE="template.json"
  if [ -f "/etc/algorand/template.json" ]; then
      cp /etc/algorand/template.json "/node/run/$TEMPLATE"
  else
      if [ "$DEV_MODE" = "1" ]; then
          TEMPLATE="devmode_template.json"
      fi
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
echo "   ALGORAND_DATA:  $ALGORAND_DATA"
echo "   NETWORK:        $NETWORK"
echo "   PROFILE:        $PROFILE"
echo "   DEV_MODE:       $DEV_MODE"
echo "   START_KMD:      ${START_KMD:-"Not Set"}"
echo "   FAST_CATCHUP:   $FAST_CATCHUP"
echo "   TOKEN:          ${TOKEN:-"Not Set"}"
echo "   ADMIN_TOKEN:    ${ADMIN_TOKEN:-"Not Set"}"
echo "   KMD_TOKEN:      ${KMD_TOKEN:-"Not Set"}"
echo "   TELEMETRY_NAME: $TELEMETRY_NAME"
echo "   NUM_ROUNDS:     $NUM_ROUNDS"
echo "   PEER_ADDRESS:   $PEER_ADDRESS"
echo "   ALGOD_PORT:     $ALGOD_PORT"

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
