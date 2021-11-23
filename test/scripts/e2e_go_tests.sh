#!/usr/bin/env bash
echo "######################################################################"
echo "  e2e_go_tests"
echo "######################################################################"
set -e
set -o pipefail

export GOPATH=$(go env GOPATH)
export GO111MODULE=on

# Needed for now because circleci doesn't use makefile yet
if [ -z "$(which gotestsum)" ]; then
    GOTESTCOMMAND=${GOTESTCOMMAND:="go test"}
else
    TEST_RESULTS=${TEST_RESULTS:="$(pwd)"}
    GOTESTCOMMAND=${GOTESTCOMMAND:="gotestsum --format testname --junitfile ${TEST_RESULTS}/results.xml --jsonfile ${TEST_RESULTS}/testresults.json --"}
fi

echo "GOTESTCOMMAND will be: ${GOTESTCOMMAND}"

# If one or more -t <pattern> are specified, use GOTESTCOMMAND -run <pattern> for each

TESTPATTERNS=()
NORACEBUILD=""
export RUN_EXPECT="FALSE"
while [ "$1" != "" ]; do
    case "$1" in
        -e)
            # The test code checks this variable.
            export RUN_EXPECT="TRUE"
            ;;
        -t)
            shift
            TESTPATTERNS+=($1)
            ;;
        -norace)
            NORACEBUILD="TRUE"
            ;;
        *)
            echo "Unknown option" "$1"
            exit 1
            ;;
    esac
    shift
done

if [[ -n $TESTPATTERNS && -n $RUN_EXPECT ]]; then
    echo "-t and -e are mutually exclusive."
    exit 1
fi

# Anchor our repo root reference location
REPO_ROOT="$( cd "$(dirname "$0")" ; pwd -P )"/../..

if [ "${NORACEBUILD}" = "" ]; then
    # Need bin-race binaries for e2e tests
    pushd ${REPO_ROOT}
    make build-race -j4
    popd
    RACE_OPTION="-race"
else
    RACE_OPTION=""
fi

# Suppress telemetry reporting for tests
export ALGOTEST=1

# Ensure our required environment variables are set - in case running this script standalone
CLEANUP_TEMPDIR=0

if [ "${TESTDIR}" = "" ]; then
    # Create our own temp folder - we'll clean it up if everything passes
    TEMPDIR=$(mktemp -d 2>/dev/null || mktemp -d -t "tmp")
    CLEANUP_TEMPDIR=1
    export TESTDIR=${TEMPDIR}
fi

echo "Test output can be found in ${TESTDIR}"

if [ "${SRCROOT}" = "" ]; then
    export SRCROOT=${REPO_ROOT}
fi

if [ "${NODEBINDIR}" = "" ]; then
    # Use the race-detector binaries, and set halt_on_error to report errors quickly.
    export PATH="${GOPATH}/bin-race:${PATH}"
    export NODEBINDIR="${GOPATH}/bin-race"
    export GORACE=halt_on_error=1
fi

if [ "${TESTDATADIR}" = "" ]; then
    export TESTDATADIR=${SRCROOT}/test/testdata
fi

echo "NODEBINDIR:  ${NODEBINDIR}"
echo "PATH:        ${PATH}"
echo "SRCROOT:     ${SRCROOT}"
echo "TESTDATADIR: ${TESTDATADIR}"

cd ${SRCROOT}/test/e2e-go

# ARM64 has some memory related issues with fork. Since we don't really care
# about testing the forking capabilities, we're just run the tests one at a time.
PARALLEL_FLAG=""
ARCHTYPE=$("${SRCROOT}/scripts/archtype.sh")
echo "ARCHTYPE:    ${ARCHTYPE}"
if [[ "${ARCHTYPE}" = arm* ]]; then
    PARALLEL_FLAG="-p 1"
fi

PACKAGES="./..."
if [ "$RUN_EXPECT" = "TRUE" ]; then
  PACKAGES=$(go list ./...|grep expect)
fi

echo "PARALLEL_FLAG = ${PARALLEL_FLAG}"
echo "PACKAGES = ${PACKAGES}"

if [ "${#TESTPATTERNS[@]}" -eq 0 ]; then
    ${GOTESTCOMMAND} ${RACE_OPTION} ${PARALLEL_FLAG} -timeout 1h -v ${SHORTTEST} ${PACKAGES}
else
    for TEST in ${TESTPATTERNS[@]}; do
        ${GOTESTCOMMAND} ${RACE_OPTION} ${PARALLEL_FLAG} -timeout 1h -v ${SHORTTEST} -run ${TEST} ${PACKAGES}
    done
fi

if [ ${CLEANUP_TEMPDIR} -ne 0 ]; then
    rm -rf "${TEMPDIR}"
fi

echo "----------------------------------------------------------------------"
echo "  DONE: e2e_go_tests"
echo "----------------------------------------------------------------------"
