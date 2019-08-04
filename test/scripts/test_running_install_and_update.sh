#!/usr/bin/env bash
echo "######################################################################"
echo "  test_running_install_and_update"
echo "######################################################################"
set -e

# Suppress telemetry reporting for tests
export ALGOTEST=1

export GOPATH=$(go env GOPATH)
REPO_DIR=$(pwd)

TESTDATA=./test/testdata

export CHANNEL=master

while [ "$1" != "" ]; do
    case "$1" in
        -c)
            shift
            export CHANNEL="$1"
            ;;
        *)
            echo "Unknown option" "$1"
            exit 1
            ;;
    esac
    shift
done

TEMPDIR=$(mktemp -d 2>/dev/null || mktemp -d -t "tmp")
echo "Test output can be found in ${TEMPDIR}"

BINDIR=${TEMPDIR}/bin
DATADIR=${TEMPDIR}/data
DATADIR2=${TEMPDIR}/data2

if [ -z "${DEFAULTNETWORK}" ]; then
    DEFAULTNETWORK=$(./scripts/compute_branch_network.sh)
fi

#----------------------
# Install the previous build and verify it runs (it should)
echo Installing LKG build to validate upgrading still runs

REFERENCE_INSTALL_CHANNEL=$(./scripts/compute_install_channel.sh "${CHANNEL}")
${GOPATH}/bin/update.sh -i -c ${REFERENCE_INSTALL_CHANNEL} -p ${BINDIR} -d ${DATADIR} -d ${DATADIR2} -n

# If genesis version changed, we don't need to test -- we only want to test non-ledger updates
OLD_GENESIS=$(${BINDIR}/algod -d ${DATADIR} -g ${DATADIR}/genesis.json -G)
echo Old Genesis = "${OLD_GENESIS}"

NEW_GENESIS=$(${GOPATH}/bin/algod -d ~/.algorand -g ${REPO_DIR}/gen/${DEFAULTNETWORK}/genesis.json -G)
echo New Genesis = "${NEW_GENESIS}"

if [ "${OLD_GENESIS}" == "${NEW_GENESIS}" ]; then
    # Configure DATADIR as Relay
    echo '{ "NetAddress": "127.0.0.1:0", "DNSBootstrapID": "" }' > ${DATADIR}/config.json
    echo '{ "DNSBootstrapID": "" }' > ${DATADIR2}/config.json

    # Copy network's wallets across the data dirs
    cp ${REPO_DIR}/gen/${DEFAULTNETWORK}/*.partkey ${DATADIR}/${OLD_GENESIS}
    mv ${DATADIR}/${OLD_GENESIS}/bank*.* ${DATADIR2}/${OLD_GENESIS}

    trap "pkill -u $(whoami) -x algod || true" 0

    # Start Relay
    ${BINDIR}/goal node start -d ${DATADIR}

    sleep 2

    # Start Node
    ${BINDIR}/goal node start -d ${DATADIR2} -p $(cat ${DATADIR}/algod-listen.net)

    # Wait up to 1 minute for the new node to connect
    echo "Waiting for network to start..."
    ${GOPATH}/bin/goal node wait -d ${DATADIR2} -w 60

    echo "Making progress - letting it run a few rounds..."
    sleep 10

    # Ensure we use the blessed genesis.json file
    export RELEASE_GENESIS_PROCESS=true
    echo "Building and installing latest build..."
    ./scripts/local_install.sh -c ${CHANNEL} -p ${BINDIR} -d ${DATADIR} -d ${DATADIR2}

    # Start Relay
    ${BINDIR}/goal node start -d ${DATADIR}
    sleep 2
    # Start Node
    ${BINDIR}/goal node start -d ${DATADIR2} -p $(cat ${DATADIR}/algod-listen.net)
    # Wait up to 1 minute for the new node to connect
    echo "Waiting for network to start..."
    ${GOPATH}/bin/goal node wait -d ${DATADIR2} -w 60
    echo "Waiting for other node to advance also..."
    ${GOPATH}/bin/goal node wait -d ${DATADIR} -w 60
fi

${BINDIR}/goal node stop -d ${DATADIR} -d ${DATADIR2}
rm -rf ${TEMPDIR}

echo "----------------------------------------------------------------------"
echo "  DONE: test_running_install_and_update"
echo "----------------------------------------------------------------------"
