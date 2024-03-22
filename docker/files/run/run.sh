#!/usr/bin/env bash

set -e

if [ "$ALGORAND_DATA" != "/algod/data" ]; then
  echo "Do not override 'ALGORAND_DATA' environment variable."
  exit 1
fi

if [ "$DEBUG" = "1" ]; then
  set -x
fi

# To allow mounting the data directory we need to change permissions
# to our algorand user. The script is initially run as the root user
# in order to change permissions, afterwards the script is re-launched
# as the algorand user.
if [ "$(id -u)" = '0' ]; then
  chown -R algorand:algorand $ALGORAND_DATA
  exec su -p -c "$(readlink -f $0) $@" algorand
fi

# Script to configure or resume a network. Based on environment settings the
# node will be setup with a private network or connect to a public network.
####################
# Helper functions #
####################

function catchup() {
  sleep 5
  goal node catchup --force --min 1000000
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

  # set profile overrides
  if [ "$GOSSIP_PORT" != "" ]; then
    algocfg -d . set -p NetAddress -v "0.0.0.0:${GOSSIP_PORT}"
    algocfg -d . set -p DisableNetworking -v "false"
    algocfg -d . set -p IncomingConnectionsLimit -v "1000"
  fi

  algocfg -d . set -p EndpointAddress -v "0.0.0.0:${ALGOD_PORT}"
  algocfg -d . set -p NodeExporterPath -v "$(which node_exporter)"

  # set token overrides
  for dir in ${ALGORAND_DATA}/../*/; do
    if [ "$TOKEN" != "" ]; then
        echo "$TOKEN" > "$dir/algod.token"
    fi
    if [ "$ADMIN_TOKEN" != "" ]; then
      echo "$ADMIN_TOKEN" > "$dir/algod.admin.token"
    fi
  done

  # configure telemetry
  if [ "$TELEMETRY_NAME" != "" ]; then
    diagcfg telemetry name -n "$TELEMETRY_NAME" -d "$ALGORAND_DATA"
    diagcfg telemetry enable -d "$ALGORAND_DATA"
  elif ! [ -f "/etc/algorand/logging.config" ]; then
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
  mkdir -p "$ALGORAND_DATA"
  cd "$ALGORAND_DATA"

  # initialize genesis.json
  if [ "$GENESIS_ADDRESS" != "" ]; then
    # download genesis file from peer
    echo "Attempting to download genesis file from $GENESIS_ADDRESS"
    curl "$GENESIS_ADDRESS/genesis" -o genesis.json
  elif [ -d "/node/run/genesis/${NETWORK}" ]; then
    echo "Installing genesis file for ${NETWORK}"
    cp "/node/run/genesis/${NETWORK}/genesis.json" genesis.json
  else
    echo "No genesis file for '$NETWORK' is available."
    exit 1
  fi

  configure_data_dir

  # if the peer address is set, it will be used instead of the DNS bootstrap ID
  if [ "$PEER_ADDRESS" != "" ]; then
    local ID
    case $NETWORK in
    mainnet) ID="<network>.algorand.network" ;;
    testnet) ID="<network>.algorand.network" ;;
    betanet) ID="<network>.algodev.network" ;;
    alphanet) ID="<network>.algodev.network" ;;
    devnet) ID="<network>.algodev.network" ;;
    *)
      echo "Unknown network."
      exit 1
      ;;
    esac

    set -p DNSBootstrapID -v "$ID"
  fi

  start_public_network
}

function start_private_network() {
  configure_data_dir
  start_kmd &

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

  # Check if keys are mounted, and if so, copy them over
  # Use pregen keys in network create command
  if [ -d "/etc/algorand/keys" ]; then
      cp -r /etc/algorand/keys /node/run/keys
      goal network create --noclean -n dockernet -r "${ALGORAND_DATA}/.." -t "/node/run/$TEMPLATE" -p "/node/run/keys"
  else
      goal network create --noclean -n dockernet -r "${ALGORAND_DATA}/.." -t "/node/run/$TEMPLATE"
  fi

  configure_data_dir
  start_private_network
}

##############
# Entrypoint #
##############

echo "Starting Algod Docker Container"
echo "   ALGORAND_DATA:   $ALGORAND_DATA"
echo "   NETWORK:         $NETWORK"
echo "   PROFILE:         $PROFILE"
echo "   DEV_MODE:        $DEV_MODE"
echo "   START_KMD:       ${START_KMD:-"Not Set"}"
echo "   FAST_CATCHUP:    $FAST_CATCHUP"
echo "   TOKEN:           ${TOKEN:-"Not Set"}"
echo "   ADMIN_TOKEN:     ${ADMIN_TOKEN:-"Not Set"}"
echo "   KMD_TOKEN:       ${KMD_TOKEN:-"Not Set"}"
echo "   TELEMETRY_NAME:  $TELEMETRY_NAME"
echo "   NUM_ROUNDS:      $NUM_ROUNDS"
echo "   GENESIS_ADDRESS: $GENESIS_ADDRESS"
echo "   PEER_ADDRESS:    $PEER_ADDRESS"
echo "   GOSSIP_PORT:     $GOSSIP_PORT"
echo "   ALGOD_PORT:      $ALGOD_PORT"

# If data directory is initialized, start existing environment.
if [ -f "$ALGORAND_DATA/../network.json" ]; then
  start_private_network
  exit 1
elif [ -f "$ALGORAND_DATA/genesis.json" ]; then
  start_public_network
  exit 1
fi

# Initialize and start network.
if [ "$NETWORK" == "" ] && [ "$PEER_ADDRESS" == "" ]; then
  start_new_private_network
else
  start_new_public_network
fi
