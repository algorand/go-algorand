#!/usr/bin/env bash
echo "######################################################################"
echo "  E2E Tests"
echo "######################################################################"
set -e

# Suppress telemetry reporting for tests
export ALGOTEST=1

SCRIPT_PATH="$( cd "$(dirname "$0")" ; pwd -P )"

SRCROOT="$(pwd -P)"

# Use same PKG_ROOT location as local_install.sh uses.
PKG_ROOT=$(pwd)/tmp/dev_pkg
rm -rf ${PKG_ROOT} # Purge existing dir if present

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

# export TEMPDIR=$(mktemp -d 2>/dev/null || mktemp -d -t "tmp")
TEST_RUN_ID=$(${SCRIPT_PATH}/testrunid.py)
export TEMPDIR=${SRCROOT}/tmp/out/e2e/${TEST_RUN_ID}
echo "Test output can be found in ${TEMPDIR}"

export BINDIR=${TEMPDIR}/bin
export DATADIR=${TEMPDIR}/data
RUNNING_COUNT=0

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

pkill -u $(whoami) -x algod || true
./scripts/local_install.sh -c ${CHANNEL} -p ${BINDIR} -d ${DATADIR}

# check our install
${BINDIR}/algod -v
${BINDIR}/goal -v

./test/scripts/goal_subcommand_sanity.sh "${BINDIR}" "${TEMPDIR}"

export PATH=${BINDIR}:${PATH}
export GOPATH=$(go env GOPATH)

# Change current directory to test/scripts so we can just use ./test.sh to exec.
cd "${SCRIPT_PATH}"

./timeout 200 ./e2e_basic_start_stop.sh

python3 -m venv ${TEMPDIR}/ve
. ${TEMPDIR}/ve/bin/activate
${TEMPDIR}/ve/bin/pip3 install --upgrade pip
${TEMPDIR}/ve/bin/pip3 install py-algorand-sdk cryptography
${TEMPDIR}/ve/bin/python3 e2e_client_runner.py e2e_subs/*.sh
deactivate

# Export our root temp folder as 'TESTDIR' for tests to use as their root test folder
# This allows us to clean up everything with our rm -rf trap.
export TESTDIR=${TEMPDIR}
export TESTDATADIR=${SRCROOT}/test/testdata
export SRCROOT=${SRCROOT}

./e2e_go_tests.sh

rm -rf ${TEMPDIR}
rm -rf ${PKG_ROOT}

echo "----------------------------------------------------------------------"
echo "  DONE: E2E"
echo "----------------------------------------------------------------------"
