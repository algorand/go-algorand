#!/usr/bin/env bash
echo "######################################################################"
echo "  E2E Tests"
echo "######################################################################"
set -e

# Suppress telemetry reporting for tests
export ALGOTEST=1

SCRIPT_PATH="$( cd "$(dirname "$0")" ; pwd -P )"

SRCROOT="$(pwd -P)"

export CHANNEL=master

HELP="Usage: $0 [-v] [-u]
Script for running go-algorand e2e tests
Requires:
    * pip
    * python 3
    * go
Options:
    -c        Channel of build you are building binaries with this script
    -n        Run tests without building binaries (Binaries are expected in PATH)
"
NO_BUILD=false
while getopts ":c:nh" opt; do
  case ${opt} in
    c ) CHANNEL=$OPTARG
      ;;
    n ) NO_BUILD=true
        GO_TEST_ARGS="-norace"
      ;;
    h ) echo "${HELP}"
        exit 0
      ;;
    \? ) echo "${HELP}"
        exit 2
      ;;
  esac
done

# export TEMPDIR=$(mktemp -d 2>/dev/null || mktemp -d -t "tmp")
TEST_RUN_ID=$(${SCRIPT_PATH}/testrunid.py)
export TEMPDIR=${SRCROOT}/tmp/out/e2e/${TEST_RUN_ID}
echo "Test output can be found in ${TEMPDIR}"

export BINDIR=${TEMPDIR}/bin
export DATADIR=${TEMPDIR}/data

function reset_dirs() {
    rm -rf ${BINDIR}
    rm -rf ${DATADIR}
    mkdir -p ${BINDIR}
    mkdir -p ${DATADIR}
}

#----------------------
# Start E2E tests by installing the current build after killing all instances
reset_dirs
echo Killing all instances and installing current build

pkill -u "$(whoami)" -x algod || true

if ! ${NO_BUILD} ; then
    ./scripts/local_install.sh -c ${CHANNEL} -p ${BINDIR} -d ${DATADIR}
    export PATH=${BINDIR}:${PATH}
fi

cp gen/devnet/genesis.json ${DATADIR}
# check our install
algod -v
goal -v

./test/scripts/goal_subcommand_sanity.sh "${TEMPDIR}"

export GOPATH=$(go env GOPATH)

# Change current directory to test/scripts so we can just use ./test.sh to exec.
cd "${SCRIPT_PATH}"

./timeout 200 ./e2e_basic_start_stop.sh


python3 -m venv "${TEMPDIR}/ve"
. "${TEMPDIR}/ve/bin/activate"
"${TEMPDIR}/ve/bin/pip3" install --upgrade pip
"${TEMPDIR}/ve/bin/pip3" install --upgrade py-algorand-sdk cryptography
"${TEMPDIR}/ve/bin/python3" e2e_client_runner.py "$SRCROOT"/test/scripts/e2e_subs/*.sh
for vdir in "$SRCROOT"/test/scripts/e2e_subs/v??; do
    "${TEMPDIR}/ve/bin/python3" e2e_client_runner.py --version "$(basename "$vdir")" "$vdir"/*.sh
done
deactivate

# Export our root temp folder as 'TESTDIR' for tests to use as their root test folder
# This allows us to clean up everything with our rm -rf trap.
export TESTDIR=${TEMPDIR}
export TESTDATADIR=${SRCROOT}/test/testdata
export SRCROOT=${SRCROOT}

./e2e_go_tests.sh ${GO_TEST_ARGS}

rm -rf "${TEMPDIR}"

if ! ${NO_BUILD} ; then
    rm -rf ${PKG_ROOT}
fi

echo "----------------------------------------------------------------------"
echo "  DONE: E2E"
echo "----------------------------------------------------------------------"
