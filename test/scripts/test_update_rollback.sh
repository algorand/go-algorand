#!/usr/bin/env bash
echo "######################################################################"
echo "  test_update_rollback"
echo "######################################################################"
set -e

# Suppress telemetry reporting for tests
export ALGOTEST=1

# Use same PKG_ROOT location as local_install.sh uses.
PKG_ROOT=$(pwd)/tmp/dev_pkg
rm -rf ${PKG_ROOT} # Purge existing dir if present
TESTDATA=$(pwd)/test/testdata

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
mkdir -p ${BINDIR}

#----------------------
# Install an old baseline build (so we're sure genesis and algod versions will have changed
echo Installing an old baseline build to update

UPDATECHANNEL=$(./scripts/compute_install_channel.sh ${CHANNEL})
UPDATESRCDIR=${TEMPDIR}/baseline
mkdir -p ${UPDATESRCDIR}
OSARCH=$(./scripts/osarchtype.sh)
TARFILE=${TESTDATA}/installs/${UPDATECHANNEL}/${OSARCH}/baseline.tar.gz

tar -zxof ${TARFILE} -C ${UPDATESRCDIR}
"${UPDATESRCDIR}/bin/update.sh" -i -r -c ${CHANNEL} -d ${DATADIR} -n -p ${BINDIR}

PREUPDATEVER="$(( ${BINDIR}/algod -v || echo 0 ) | head -n 1)"
PREUPDATEGENESIS=$(${BINDIR}/algod -d ${DATADIR} -g ${DATADIR}/genesis.json -G)

# Now update previous build to latest version - this should result in no nodes running
./scripts/local_install.sh -c ${CHANNEL} -p ${BINDIR} -d ${DATADIR} -f -testrollback
./test/scripts/verify_build.sh -c ${UPDATECHANNEL} -p ${BINDIR} -d ${DATADIR}

POSTUPDATEVER="$(( ${BINDIR}/algod -v || echo 0 ) | head -n 1)"
POSTUPDATEGENESIS=$(${BINDIR}/algod -d ${DATADIR} -g ${DATADIR}/genesis.json -G)

if [ ${PREUPDATEVER} != ${POSTUPDATEVER} ]; then
    echo "algod version changed after rolling back update - this is an error"
    exit 1
fi

if [ ${PREUPDATEGENESIS} != ${POSTUPDATEGENESIS} ]; then
    echo "Genesis version changed after rolling back update - this is an error"
    exit 1
fi

rm -rf ${TEMPDIR}
rm -rf ${PKG_ROOT}

echo "----------------------------------------------------------------------"
echo "  DONE: test_update_rollback"
echo "----------------------------------------------------------------------"
