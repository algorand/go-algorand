#!/bin/bash

FILENAME=$(basename -- "$0")
SCRIPTPATH="$( cd "$(dirname "$0")" ; pwd -P )"
UPDATETYPE="update"
INSTALLOPT="-u"
RESUME_INSTALL=0
BINDIR=""
CHANNEL=""
DATADIRS=()
NOSTART=""
BINDIRSPEC="-p ${SCRIPTPATH}"
DATADIRSPEC=""
TESTROLLBACK=""
UNKNOWNARGS=()
HOSTEDFLAG=""
HOSTEDSPEC=""
BUCKET=""
GENESIS_NETWORK_DIR=""
GENESIS_NETWORK_DIR_SPEC=""

# If someone set the environment variable asking us to cleanup
# when we're done, install a trap to do so
# We use an environment variable instead of an arg because
# older scripts won't recognize it and will fail (an issue with tests)
if [ "${CLEANUP_UPDATE_TEMP_DIR}" != "" ]; then
    trap "rm -rf ${CLEANUP_UPDATE_TEMP_DIR}" 0
fi

while [ "$1" != "" ]; do
    case "$1" in
        -i)
            UPDATETYPE="install"
            INSTALLOPT="-i"
            ;;
        -u)
            UPDATETYPE="update"
            INSTALLOPT="-u"
            ;;
        -m)
            UPDATETYPE="migrate"
            INSTALLOPT="-m"
            ;;
        -r)
            RESUME_INSTALL=1
            ;;
        -c)
            shift
            CHANNEL="$1"
            ;;
        -d)
            shift
            THISDIR=$1
            mkdir -p ${THISDIR} >/dev/null
            pushd ${THISDIR} >/dev/null
            THISDIR=$(pwd -P)
            popd >/dev/null
            DATADIRS+=(${THISDIR})
            DATADIRSPEC+="-d ${THISDIR} "
            ;;
        -p)
            shift
            BINDIR="$1"
            BINDIRSPEC="-p $1"
            ;;
        -n)
            NOSTART="-n"
            ;;
        -testrollback)
            TESTROLLBACK=1
            ;;
        -hosted)
            HOSTEDFLAG="-H"
            HOSTEDSPEC="-hosted"
            ;;
        -g)
            shift
            GENESIS_NETWORK_DIR=$1
            GENESIS_NETWORK_DIR_SPEC="-g $1"
            ;;
        -b)
            shift
            BUCKET="-b $1"
            ;;
        *)
            echo "Unknown option" "$1"
            UNKNOWNARGS+=("$1")
            ;;
    esac
    shift
done

# If this is an update, we'll validate that before doing anything else.
# If this is an install, we'll create it.
if [ ${RESUME_INSTALL} -eq 0 ]; then
    if [ "${BINDIR}" = "" ]; then
        BINDIR="${SCRIPTPATH}"
    fi
fi

# If -d not specified, don't default any more
if [ "${#DATADIRS[@]}" -eq 0 ]; then
    echo "You must specify at least one data directory with `-d`"
    exit 1
fi

CURRENTVER=0

ROLLBACK=0
ROLLBACKBIN=0
ROLLBACKDATA=()
NEW_LEDGER=0
RESTART_NODE=0

function check_install_valid() {
    # Check for key files that indicate a valid install that can be updated
    if [ ! -f "${BINDIR}/algod" ]; then
        echo "Missing ${BINDIR}/algod"
        return 1
    fi
    return 0
}

function validate_channel_specified() {
    if [ "${CHANNEL}" = "" ]; then
        CHANNEL="$((${BINDIR}/algod -c) | head -n 1)"
        if [ "${CHANNEL}" = "" ]; then
            echo "Unable to determine release channel - please run again with -c <channel>"
            return 1
        fi
    fi
}

function determine_current_version() {
    CURRENTVER="$(( ${BINDIR}/algod -v || echo 0 ) | head -n 1)"
    echo Current Version = ${CURRENTVER}
}

function check_for_update() {
    determine_current_version
    LATEST="$(${SCRIPTPATH}/updater ver check -c ${CHANNEL} ${BUCKET} | sed -n '2 p')"
    if [ $? -ne 0 ]; then
        echo No remote updates found
        return 1
    fi

    echo Latest Version = ${LATEST}

    if [ ${CURRENTVER} -ge ${LATEST} ]; then
        if [ "${UPDATETYPE}" = "install" ]; then
            echo No new version found - forcing install anyway
        else
            echo No new version found
            return 1
        fi
    fi

    echo New version found
    return 0
}

TEMPDIR=""
TARFILE=""
UPDATESRCDIR=""

function download_update() {
    SPECIFIC_VERSION=$1
    TEMPDIR=$(mktemp -d 2>/dev/null || mktemp -d -t "tmp")
    export CLEANUP_UPDATE_TEMP_DIR=${TEMPDIR}
    trap "rm -rf ${CLEANUP_UPDATE_TEMP_DIR}" 0

    TARFILE=${TEMPDIR}/${LATEST}.tar.gz
    UPDATESRCDIR=${TEMPDIR}/a
    mkdir ${UPDATESRCDIR}

    ${SCRIPTPATH}/updater ver get -c ${CHANNEL} -o ${TARFILE} ${BUCKET} ${SPECIFIC_VERSION}

    if [ $? -ne 0 ]; then
        echo Error downloading update file
        exit 1
    fi
    echo Update Downloaded to ${TARFILE}
}

function check_and_download_update() {
    check_for_update
    if [ $? -ne 0 ]; then return 1; fi

    download_update
}

function download_update_for_current_version() {
    determine_current_version
    echo "Downloading update package for current version ${CURRENTVER}..."
    download_update "-v ${CURRENTVER}"
}

function expand_update() {
    echo Expanding update...

    tar -zxof ${TARFILE} -C ${UPDATESRCDIR}
    if [ $? -ne 0 ]; then return 1; fi

    validate_update
}

function validate_update() {
    echo Validating update...
    # We should consider including a version.info file
    # that we can compare against the expected version
    return 0
}

function shutdown_node() {
    echo Stopping node...
    if [ "$(pgrep -x algod)" != "" ] || [ "$(pgrep -x kmd)" != "" ] ; then
        if [ -f ${BINDIR}/goal ]; then
            for DD in ${DATADIRS[@]}; do
                if [ -f ${DD}/algod.pid ] || [ -f ${DD}/**/kmd.pid ] ; then
                    echo Stopping node and waiting...
                    sudo -n systemctl stop algorand@$(systemd-escape ${DD})
                    ${BINDIR}/goal node stop -d ${DD}
                    sleep 5
                else
                    echo "Node is running but not in ${DD} - not stopping"
                    # Clean up zombie (algod|kmd).net files
                    rm -f ${DD}/algod.net ${DD}/**/kmd.net
                fi
            done
        fi
    else
        echo ... node not running
    fi

    RESTART_NODE=1
}

function backup_binaries() {
    echo Backing up current binary files...
    mkdir -p ${BINDIR}/backup
    BACKUPFILES="algod kmd carpenter doberman goal update.sh updater diagcfg"
    # add node_exporter to the files list we're going to backup, but only we if had it previously deployed.
    [ -f ${BINDIR}/node_exporter ] && BACKUPFILES="${BACKUPFILES} node_exporter"
    tar -zcf ${BINDIR}/backup/bin-v${CURRENTVER}.tar.gz -C ${BINDIR} ${BACKUPFILES} >/dev/null 2>&1
}

function backup_data() {
    CURDATADIR=$1
    BACKUPDIR="${CURDATADIR}/backup"

    echo "Backing up current data files from ${CURDATADIR}..."
    mkdir -p ${BACKUPDIR}
    BACKUPFILES="genesis.json wallet-genesis.id"
    tar --no-recursion --exclude='*.log' --exclude='*.log.archive' --exclude='*.tar.gz' -zcf ${BACKUPDIR}/data-v${CURRENTVER}.tar.gz -C ${CURDATADIR} ${BACKUPFILES} >/dev/null 2>&1
}

function backup_current_version() {
    backup_binaries
    for DD in ${DATADIRS[@]}; do
        backup_data ${DD}
    done
}

function rollback_binaries() {
    echo "Rolling back binary files..."
    tar -zxof ${BINDIR}/backup/bin-v${CURRENTVER}.tar.gz -C ${BINDIR}
}

function rollback_data() {
    CURDATADIR=$1
    BACKUPDIR="${CURDATADIR}/backup"

    echo "Rolling back data files in ${CURDATADIR}..."
    rm ${CURDATADIR}/wallet-genesis.id
    tar -zxof ${BACKUPDIR}/data-v${CURRENTVER}.tar.gz -C ${CURDATADIR}
}

function install_new_binaries() {
    if [ ! -d ${UPDATESRCDIR}/bin ]; then
        return 0
    else
        echo Installing new binary files...
        ROLLBACKBIN=1
        rm -rf ${BINDIR}/new
        mkdir ${BINDIR}/new
        cp ${UPDATESRCDIR}/bin/* ${BINDIR}/new
        mv ${BINDIR}/new/* ${BINDIR}
        rm -rf ${BINDIR}/new
    fi
}

function reset_wallets_for_new_ledger() {
    CURDATADIR=$1

    echo "New Ledger - restoring genesis accounts in ${CURDATADIR}"
    pushd ${CURDATADIR} >/dev/null
    mkdir -p "${NEW_VER}"
    for file in *.partkey *.rootkey; do
        if [ -e "${file}" ]; then
            cp "${file}" "${NEW_VER}/${file}"
            echo 'Installed genesis account file: ' "${file}"
        fi
    done
    popd >/dev/null
}

function import_rootkeys() {
    CURDATADIR=$1

    echo "New Ledger - importing rootkeys for genesis accounts"
    ${BINDIR}/goal account importrootkey -u -d ${CURDATADIR}
}

function install_new_data() {
    if [ ! -d ${UPDATESRCDIR}/data ]; then
        return 0
    else
        CURDATADIR=$1
        echo "Installing new data files into ${CURDATADIR}..."
        ROLLBACKDATA+=(${CURDATADIR})
        cp ${UPDATESRCDIR}/data/* ${CURDATADIR}
    fi
}

function copy_genesis_files() {
    echo "Copying genesis files locally"
    cp -rf ${UPDATESRCDIR}/genesis/ ${BINDIR}/genesisfiles/
}

function check_for_new_ledger() {
    CURDATADIR=$1
    echo "Checking for new ledger in ${CURDATADIR}"
    EXISTING_VER=$(${UPDATESRCDIR}/bin/algod -d ${CURDATADIR} -g ${CURDATADIR}/genesis.json -G)

    if [ -z $EXISTING_VER ]; then
        if [ -z ${GENESIS_NETWORK_DIR} ]; then
            echo "Updating genesis files for default network"
        else
            echo "Installing genesis files for network ${GENESIS_NETWORK_DIR}"
        fi
    else
        GENESIS_SPLIT=(${EXISTING_VER//-/ })
        GENESIS_NETWORK_DIR=${GENESIS_SPLIT[0]}
        echo "Updating genesis files for network ${GENESIS_NETWORK_DIR}"

        # If that genesis dir doesn't exist, use the default file - this is likely a custom network build
        if [ ! -d ${UPDATESRCDIR}/genesis/${GENESIS_NETWORK_DIR} ]; then
            GENESIS_NETWORK_DIR=""
        fi
    fi

    NEW_VER=$(${UPDATESRCDIR}/bin/algod -d ${CURDATADIR} -g ${UPDATESRCDIR}/genesis/${GENESIS_NETWORK_DIR}/genesis.json -G)
    if [ $? -ne 0 ]; then
        echo "Cannot determine new genesis ID. Not updating. This may be a problem!"
        return 1
    fi

    # Copy new genesis.json even if version didn't change; we might have
    # changed the file itself in a compatible way.
    cp ${UPDATESRCDIR}/genesis/${GENESIS_NETWORK_DIR}/genesis.json ${CURDATADIR}

    echo ${NEW_VER} > ${CURDATADIR}/wallet-genesis.id
    if [ "${NEW_VER}" != "${EXISTING_VER}" ]; then
        echo "New genesis ID, resetting wallets"
        NEW_LEDGER=1
        reset_wallets_for_new_ledger ${CURDATADIR}

        import_rootkeys ${CURDATADIR}
    fi
}

# Delete all logs.
function clean_legacy_logs() {
    CURDATADIR=$1

    echo "Deleting existing log files in ${CURDATADIR}"
    rm -f ${CURDATADIR}/node-*.log
    rm -f ${CURDATADIR}/node-*.log.archive
    return 0
}

function startup_node() {
    if [ "${NOSTART}" != "" ]; then
        echo Auto-start node disabled - not starting
        return
    fi

    CURDATADIR=$1
    echo Starting node in ${CURDATADIR}...

    check_install_valid
    if [ $? -ne 0 ]; then
        fail_and_exit "Installation does not appear to be valid"
    fi

    sudo -n systemctl start algorand@$(systemd-escape ${CURDATADIR})
    if [ $? -ne 0 ]; then
        ${BINDIR}/goal node start -d ${CURDATADIR} ${HOSTEDFLAG}
    fi
}

function startup_nodes() {
    for DD in ${DATADIRS[@]}; do
        startup_node ${DD}
    done
}

function rollback() {
    echo Rolling back from failed update...
    if [ ${ROLLBACKBIN} -ne 0 ]; then
        rollback_binaries
    fi
    for ROLLBACKDIR in ${ROLLBACKDATA[@]}; do
        rollback_data ${ROLLBACKDIR}
    done
}

function fail_and_exit() {
    echo "*** UPDATE FAILED: $1 ***"
    if [ ${ROLLBACK} -ne 0 ]; then
        ROLLBACK=0
        rollback
        check_install_valid
        if [ ${RESTART_NODE} -ne 0 ]; then
            startup_nodes
        fi
        exit 0
    fi
    exit 1
}

function apply_fixups() {
    echo "Applying migration fixups..."

    # Delete obsolete algorand binary - renamed to 'goal'
    rm ${BINDIR}/algorand >/dev/null 2>&1

    for DD in ${DATADIRS[@]}; do
        clean_legacy_logs ${DD}

        # Purge obsolete cadaver files (now agreement.cdv[.archive])
        rm -f ${DD}/service*.cadaver
    done
}

#--------------------------------------------
# Main Update Driver

# Need to verify the bindir was specified (with -p)
# and that it's a valid directory.
# Unless it's an install
if [ ! -d "${BINDIR}" ]; then
    if [ "${UPDATETYPE}" = "install" ]; then
        mkdir -p ${BINDIR}
    else
        fail_and_exit "Missing or invalid binaries path specified '${BINDIR}'"
    fi
fi

if [ "${UPDATETYPE}" != "install" ]; then
    check_install_valid
    if [ $? -ne 0 ]; then
        echo "Unable to perform an update - installation does not appear valid"
        exit 1
    fi
fi

# If we're initiating an update/install, check for an update and if we have a new one,
# expand it and invoke the new update.sh script.
if [ ${RESUME_INSTALL} -eq 0 ]; then
    validate_channel_specified

    if [ "${UPDATETYPE}" = "migrate" ]; then
        download_update_for_current_version
    else
        check_and_download_update
    fi

    if [ $? -ne 0 ]; then
        # No update - stop here
        exit $?
    fi

    expand_update
    if [ $? -ne 0 ]; then
        fail_and_exit "Error expanding update"
    fi

    # Spawn the new update script and exit - this allows us to push update.sh changes that take effect immediately
    # Note that the SCRIPTPATH we're passing in should be our binaries directory, which is what we expect to be
    # passed as the last argument (if any)
    echo "Starting the new update script to complete the installation..."
    exec "${UPDATESRCDIR}/bin/${FILENAME}" ${INSTALLOPT} -r -c ${CHANNEL} ${DATADIRSPEC} ${NOSTART} ${BINDIRSPEC} ${HOSTEDSPEC} ${GENESIS_NETWORK_DIR_SPEC} "${UNKNOWNARGS[@]}"

    # If we're still here, exec failed.
    fail_and_exit "Error executing the new update script - unable to continue"
else
    # We're running the script from our expanded update, which is located in the last script's ${TEMPDIR}/a/bin
    # We need to define our TEMPDIR and UPDATESRCDIR to match those values; we do so by making them relative
    # to where our resuming script lives.
    TEMPDIR=${SCRIPTPATH}/../..
    UPDATESRCDIR=${SCRIPTPATH}/..
    echo "... Resuming installation from the latest update script"

    determine_current_version
fi

# Shutdown node before backing up so data is consistent and files aren't locked / in-use.
shutdown_node

backup_current_version

# We don't care about return code - doesn't matter if we failed to archive

ROLLBACK=1

install_new_binaries
if [ $? -ne 0 ]; then
    fail_and_exit "Error installing new files"
fi

for DD in ${DATADIRS[@]}; do
    install_new_data ${DD}
    if [ $? -ne 0 ]; then
        fail_and_exit "Error installing data files into ${DD}"
    fi
done

copy_genesis_files

for DD in ${DATADIRS[@]}; do
    check_for_new_ledger ${DD}
    if [ $? -ne 0 ]; then
        fail_and_exit "Error updating ledger in ${DD}"
    fi
done

if [ "${TESTROLLBACK}" != "" ]; then
    fail_and_exit "Simulating update failure - rolling back"
fi

apply_fixups

if [ "${NOSTART}" != "" ]; then
    echo "Install complete - restart node manually"
else
    startup_nodes
fi

exit 0
