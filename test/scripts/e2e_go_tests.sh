#!/usr/bin/env bash
echo "######################################################################"
echo "  e2e_go_tests"
echo "######################################################################"
set -e

export GOPATH=$(go env GOPATH)
export GO111MODULE=on

# Anchor our repo root reference location
REPO_ROOT="$( cd "$(dirname "$0")" ; pwd -P )"/../..

# Need bin-race binaries for e2e tests
pushd ${REPO_ROOT}
make build-race -j4
popd

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

cd ${SRCROOT}/test/e2e-go

# For now, disable long-running e2e tests on Travis
# (the ones that won't complete...)
SHORTTEST=
if [ "${TRAVIS_BRANCH}" != "" ]; then
    SHORTTEST=-short
fi

# If one or more -t <pattern> are specified, use go test -run <pattern> for each

TESTPATTERNS=()

while [ "$1" != "" ]; do
    case "$1" in
        -t)
            shift
            TESTPATTERNS+=($1)
            ;;
        *)
            echo "Unknown option" "$1"
            exit 1
            ;;
    esac
    shift
done

if [ "${#TESTPATTERNS[@]}" -eq 0 ]; then
    go test -race -timeout 1h -v ${SHORTTEST} ./...
else
    for TEST in ${TESTPATTERNS[@]}; do
        go test -race -timeout 1h -v ${SHORTTEST} -run ${TEST} ./...
    done
fi

if [ ${CLEANUP_TEMPDIR} -ne 0 ]; then
    rm -rf ${TEMPDIR}
fi

echo "----------------------------------------------------------------------"
echo "  DONE: e2e_go_tests"
echo "----------------------------------------------------------------------"
