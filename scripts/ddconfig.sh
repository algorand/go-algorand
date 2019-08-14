#!/bin/bash

set -ex

SCRIPTPATH="$( pushd "$(dirname "$0")" ; pwd -P )" >/dev/null
popd >/dev/null

function ShowSyntaxAndExit() {
    echo "ddconfig - enable or disable DataDog for use with an Algorand host"
    echo "Syntax: ddconfig enable -d <datadir> -p <port> -n <hostname> -k <apikey>"
    echo "Syntax: ddconfig disable"
    echo "Do not run as root / sudo - you will be prompted to elevate if necessary"
    exit 2
}

function DisableAndExit() {
    sudo systemctl stop datadog-agent
    sudo systemctl disable datadog-agent
    exit 0
}

DATADIR=
PORT=
HOSTNAME=
APIKEY=

# ddconfig enable -p 8880 -n r-aa.mainnet -k <apikey> -d ~/algorand/node

CMD="$1"
shift

if [[ "${CMD}" = "disable" ]]; then
    DisableAndExit
fi

if [[ "${CMD}" != "enable" ]]; then
    ShowSyntaxAndExit
fi

while [[ "$1" != "" ]]; do
    case "$1" in
        -d)
            shift
            DATADIR=$1
            pushd ${DATADIR} >/dev/null
            DATADIR=$(pwd -P)
            popd >/dev/null
            ;;
        -p)
            shift
            PORT=$1
            PORT=$(echo $1 | grep -o ":[0-9]*" | tr -d ":")
            if [[ -z "${PORT}" ]]; then
                echo "Port value does not appear to be valid.  Specify just the port (eg -p 8000)"
                exit 1
            fi
            ;;
        -n)
            shift
            HOSTNAME=$1
            ;;
        -k)
            shift
            APIKEY=$1
            ;;
        -h)
            ShowSyntaxAndExit
            ;;
        *)
            echo "Unknown option:" "$1"
            ;;
    esac
    shift
done

if [[ -z "${DATADIR}" || -z "${HOSTNAME}" || -z "${APIKEY}" ]]; then
    ShowSyntaxAndExit
fi

ENDPOINT=$(${SCRIPTPATH}/algocfg get -p EndpointAddress -d "$DATADIR")
ADDRESS=$(echo ${ENDPOINT} | grep -o "[0-9\.]*:" | tr -d ":")

if [[ -z "${PORT}" ]]; then
    PORT=$(echo ${ENDPOINT} | grep -o ":[0-9]*" | tr -d ":")
    if [[ -z "${PORT}" || "${PORT}" = "0" ]]; then
        echo "Port not specified and not already configured - please specify a port to use with `-p`"
        exit 1
    fi
fi

# Validate the APIKEY - should be 32 alphanum (lowercase) chars
if [[ "${#APIKEY}" != "32" ]]; then
    echo "API Key specified should be 32 characters long"
    exit 1
fi
FILTEREDKEY=$(echo ${APIKEY} | grep -o "[0-9a-f]*")
if [[ "${APIKEY}" != "${FILTEREDKEY}" ]]; then
    echo "API Key specified should contain only lowercase characters or numbers"
    exit 1
fi

# At this point we should have valid PORT, HOSTNAME, APIKEY, and DATADIR
# Apply the algod changes and restart it
# Install DataDog agent, configure it, and restart it

${SCRIPTPATH}/diagcfg metric disable

$(${SCRIPTPATH}/algocfg set -p EndpointAddress -d "$DATADIR" -v "${ADDRESS}:${PORT}"

${SCRIPTPATH}/goal node restart -d ${DATADIR}
pkill node_exporter || true

# Install DataDog Agent
DD_API_KEY=${APIKEY} bash -c "$(curl -L https://raw.githubusercontent.com/DataDog/datadog-agent/master/cmd/agent/install_script.sh)"

# Remove existing "hostname:" line if any, then append the new one
sudo sed /[[:space:]#]hostname:/d /etc/datadog-agent/datadog.yaml | sed /^hostname:/d > /etc/datadog-agent/datadog.yaml.tmp
sudo echo "hostname: $HOSTNAME" >> /etc/datadog-agent/datadog.yaml.tmp
sudo mv /etc/datadog-agent/datadog.yaml.tmp /etc/datadog-agent/datadog.yaml

set ALGOD_PORT=8880
set ALGOD_TOKEN$(cat "${DATADIR}/algod.token)"

sudo mkdir -p /etc/datadog-agent/conf.d/prometheus.d

sudo cat <<EOF>/etc/datadog-agent/conf.d/prometheus.d/conf.yaml
init_config:
 
instances:
  - prometheus_url: http://localhost:$(ALGOD_PORT)/metrics
    extra_headers:
      X-Algo-API-Token: ${ALGOD_TOKEN)
    namespace: algod
    metrics:
      - algod*
EOF

# Restart datadog agent to pick up hostname and prometheus settings
sudo systemctl restart datadog-agent
