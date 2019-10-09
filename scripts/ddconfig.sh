#!/usr/bin/env bash

set -ex

SCRIPTPATH="$(cd "$(dirname "$0")" ; pwd -P )" >/dev/null

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

function PrintEndpointAddress() {
  if [[ -f "$1/algocfg" ]]; then
    echo $($1/algocfg get -p EndpointAddress -d "$2")
  else
    echo $(cat $2/config.json|grep EndpointAddress|cut -f 4 -d\")
  fi
}

function SetEndpointAddress() {
  if [[ -f "$1/algocfg" ]]; then
    $($1/algocfg set -p EndpointAddress -d "$2" -v "$3")
  else
    $(sed -i -e 's/.*EndpointAddress.*/    "EndpointAddress": "'"$3"'","/' "$2/config.json")
  fi
}

DATADIR=
PORT=
HOSTNAME=
APIKEY=

# ddconfig enable -p 8880 -n r-aa.mainnet -k <apikey> -d ~/algorand/node

CMD="$1"

if [[ "${CMD}" = "disable" ]]; then
    DisableAndExit
fi

if [[ "${CMD}" != "enable" ]]; then
    ShowSyntaxAndExit
fi

shift

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
            PORT=$(echo $1 | grep -o "[0-9]*")
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

ENDPOINT="$(PrintEndpointAddress $SCRIPTPATH $DATADIR)"
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

${SCRIPTPATH}/diagcfg metric disable -d "${DATADIR}"

SetEndpointAddress $SCRIPTPATH $DATADIR "${ADDRESS}:${PORT}"

${SCRIPTPATH}/goal node stop -d ${DATADIR}
pkill node_exporter || true

if [[ ! -f "${DATADIR}/algod.token" ]]; then
    ${SCRIPTPATH}/goal node generatetoken -d "${DATADIR}"
fi

ALGOD_TOKEN=$(cat "${DATADIR}/algod.token")
${SCRIPTPATH}/goal node start -d "${DATADIR}"


# Install DataDog Agent
DD_API_KEY=${APIKEY} bash -c "$(curl -L https://raw.githubusercontent.com/DataDog/datadog-agent/master/cmd/agent/install_script.sh)"

# Remove existing "hostname:" line if any, then append the new one
sudo sed /[[:space:]#]hostname:/d /etc/datadog-agent/datadog.yaml | sudo sed /^hostname:/d > ~/datadog.yaml.tmp
sudo echo "hostname: $HOSTNAME" >> ~/datadog.yaml.tmp
sudo mv ~/datadog.yaml.tmp /etc/datadog-agent/datadog.yaml

sudo mkdir -p /etc/datadog-agent/conf.d/prometheus.d

cat <<EOF>~/conf.yaml.tmp
init_config:
 
instances:
  - prometheus_url: http://localhost:${PORT}/metrics
    extra_headers:
      X-Algo-API-Token: ${ALGOD_TOKEN}
    namespace: algod
    metrics:
      - algod*
EOF

sudo mv ~/conf.yaml.tmp /etc/datadog-agent/conf.d/prometheus.d/conf.yaml

# Restart datadog agent to pick up hostname and prometheus settings
sudo systemctl restart datadog-agent
