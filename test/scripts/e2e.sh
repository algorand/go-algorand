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
    -i        Start an interactive session for running e2e subs.
"
NO_BUILD=false
while getopts ":c:nhi" opt; do
  case ${opt} in
    c ) CHANNEL=$OPTARG
      ;;
    n ) NO_BUILD=true
        GO_TEST_ARGS="-norace"
      ;;
    h ) echo "${HELP}"
        exit 0
    ;;
    i ) echo "  Interactive session"
        echo "######################################################################"
        INTERACTIVE=true
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

function cleanup() {
  echo "Cleaning up temp dir."

  rm -rf "${TEMPDIR}"

  if ! ${NO_BUILD} ; then
      rm -rf ${PKG_ROOT}
  fi
}

# Cleanup files created during tests.
trap cleanup EXIT

# ARM64 has an unoptimized scrypt() which can cause tests to timeout.
# Run kmd with scrypt() configured to run less secure and fast to go through the motions for test.
# thus, on those platforms we launch kmd with unsafe_scrypt = true to speed up the tests.
RUN_KMD_WITH_UNSAFE_SCRYPT=""
PLATFORM_ARCHTYPE=$("${SRCROOT}/scripts/archtype.sh")

echo "ARCHTYPE:    ${PLATFORM_ARCHTYPE}"
if [[ "${PLATFORM_ARCHTYPE}" = arm* ]]; then
    RUN_KMD_WITH_UNSAFE_SCRYPT="--unsafe_scrypt"
fi

echo "RUN_KMD_WITH_UNSAFE_SCRYPT = ${RUN_KMD_WITH_UNSAFE_SCRYPT}"

export BINDIR=${TEMPDIR}/bin
export DATADIR=${TEMPDIR}/data
export NETWORKDIR=${TEMPDIR}/net

function reset_dirs() {
    rm -rf ${BINDIR}
    rm -rf ${DATADIR}
    rm -rf ${NETWORKDIR}
    mkdir -p ${BINDIR}
    mkdir -p ${DATADIR}
    mkdir -p ${NETWORKDIR}
}

# $1 - Message
LAST_DURATION=$SECONDS
function duration() {
  ELAPSED=$((SECONDS - $LAST_DURATION))
  printf "Duration: '%s' - %02dh:%02dm:%02ds\n" "$1" $(($ELAPSED/3600)) $(($ELAPSED%3600/60)) $(($ELAPSED%60))
  LAST_DURATION=$SECONDS
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

# check our install
algod -v
goal -v

./test/scripts/goal_subcommand_sanity.sh "${TEMPDIR}"

export GOPATH=$(go env GOPATH)

# Change current directory to test/scripts so we can just use ./test.sh to exec.
cd "${SCRIPT_PATH}"

if [ -z "$E2E_TEST_FILTER" ] || [ "$E2E_TEST_FILTER" == "SCRIPTS" ]; then
    python3 -m venv "${TEMPDIR}/ve"
    . "${TEMPDIR}/ve/bin/activate"
    "${TEMPDIR}/ve/bin/pip3" install --upgrade pip

    # Pin major version of our python SDK's so that breaking changes
    # don't spuriously break our tests.  If a minor version breaks our
    # tests, we ought to find out.
    "${TEMPDIR}/ve/bin/pip3" install 'py-algorand-sdk==2.*'

    # Enable remote debugging:
    "${TEMPDIR}/ve/bin/pip3" install --upgrade debugpy
    duration "e2e client setup"

    if [ $INTERACTIVE ]; then
        echo -e "\n\n********** READY **********\n\n"
        echo "The test environment is now set. You can now run tests in another terminal."

        echo -e "\nConfigure the environment:\n"
        if [ "$(basename $SHELL)" == "fish" ]; then
            echo "set -g VIRTUAL_ENV \"${TEMPDIR}/ve\""
            echo "set -g PATH \"\$VIRTUAL_ENV/bin:\$PATH\""
        else
            echo "export VIRTUAL_ENV=\"${TEMPDIR}/ve\""
            echo "export PATH=\"\$VIRTUAL_ENV/bin:\$PATH\""
        fi

        echo ""
        echo "python3 \"$SCRIPT_PATH/e2e_client_runner.py\" ${RUN_KMD_WITH_UNSAFE_SCRYPT} \"$SCRIPT_PATH/e2e_subs/SCRIPT_FILE_NAME\""
        echo ""
        echo "Press enter to shut down the test environment..."
        read a
        echo -n "deactivating..."
        deactivate
        echo "done"
        exit
    fi

    goal network create \
      -r $NETWORKDIR \
      -n tbd \
      -t ../testdata/nettemplates/TwoNodes50EachFuture.json

    ./timeout 200 ./e2e_basic_start_stop.sh $NETWORKDIR
    duration "e2e_basic_start_stop.sh"

    goal network delete -r $NETWORKDIR

    KEEP_TEMPS_CMD_STR=""

    # If the platform is arm64, we want to pass "--keep-temps" into e2e_client_runner.py
    # so that we can keep the temporary test artifact for use in the indexer e2e tests.
    # The file is located at ${TEMPDIR}/net_done.tar.bz2
    if [ -n "$CI_KEEP_TEMP_PLATFORM" ] && [ "$CI_KEEP_TEMP_PLATFORM" == "$CI_PLATFORM" ]; then
      echo "Setting --keep-temps so that an e2e artifact can be saved."
      KEEP_TEMPS_CMD_STR="--keep-temps"
    fi


    clientrunner="${TEMPDIR}/ve/bin/python3 e2e_client_runner.py ${RUN_KMD_WITH_UNSAFE_SCRYPT}"

    $clientrunner ${KEEP_TEMPS_CMD_STR} "$SRCROOT"/test/scripts/e2e_subs/*.{sh,py}

    # If the temporary artifact directory exists, then the test artifact needs to be created
    if [ -d "${TEMPDIR}/net" ]; then
        # This should be set by CI, but if it isn't set a default.
        if [ -z "$CI_E2E_FILENAME" ]; then
          CI_E2E_FILENAME="net_done"
        fi

        pushd "${TEMPDIR}" || exit 1
        tar -j -c -f "${CI_E2E_FILENAME}.tar.bz2" --exclude node.log --exclude agreement.cdv net
        rm -rf "${TEMPDIR}/net"
        RSTAMP=$(TZ=UTC python -c 'import time; print("{:08x}".format(0xffffffff - int(time.time() - time.mktime((2020,1,1,0,0,0,-1,-1,-1)))))')
        echo aws s3 cp --acl public-read "${TEMPDIR}/${CI_E2E_FILENAME}.tar.bz2" "s3://algorand-testdata/indexer/e2e4/${RSTAMP}/${CI_E2E_FILENAME}.tar.bz2"
        aws s3 cp --acl public-read "${TEMPDIR}/${CI_E2E_FILENAME}.tar.bz2" "s3://algorand-testdata/indexer/e2e4/${RSTAMP}/${CI_E2E_FILENAME}.tar.bz2"
        popd
    fi

    duration "parallel client runner"

    for vdir in "$SRCROOT"/test/scripts/e2e_subs/v??; do
        $clientrunner --version "$(basename "$vdir")" "$vdir"/*.sh
    done
    duration "vdir client runners"

    for script in "$SRCROOT"/test/scripts/e2e_subs/serial/*; do
        $clientrunner "$script"
    done

    deactivate
    duration "serial client runners"
fi # if E2E_TEST_FILTER == "" or == "SCRIPTS"

if [ -z "$E2E_TEST_FILTER" ] || [ "$E2E_TEST_FILTER" == "GO" ]; then
    # Export our root temp folder as 'TESTDIR' for tests to use as their root test folder
    # This allows us to clean up everything with our rm -rf trap.
    mkdir "${TEMPDIR}/go"
    export TESTDIR=${TEMPDIR}/go
    export TESTDATADIR=${SRCROOT}/test/testdata
    export SRCROOT=${SRCROOT}

    ./e2e_go_tests.sh ${GO_TEST_ARGS}
    duration "go integration tests"
fi # if E2E_TEST_FILTER == "" or == "GO"

if [ -z "$E2E_TEST_FILTER" ] || [ "$E2E_TEST_FILTER" == "EXPECT" ]; then
    # Export our root temp folder as 'TESTDIR' for tests to use as their root test folder
    # This allows us to clean up everything with our rm -rf trap.
    mkdir "${TEMPDIR}/expect"
    export TESTDIR=${TEMPDIR}/expect
    export TESTDATADIR=${SRCROOT}/test/testdata
    export SRCROOT=${SRCROOT}

    ./e2e_go_tests.sh -e ${GO_TEST_ARGS}
    duration "expect tests"
fi # if E2E_TEST_FILTER == "" or == "EXPECT"

echo "----------------------------------------------------------------------"
echo "  DONE: E2E"
echo "----------------------------------------------------------------------"
