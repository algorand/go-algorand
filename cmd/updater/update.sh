#!/bin/bash
# shellcheck disable=2009,2093,2164

UPDATER_MIN_VERSION="3.12.2"
UPDATER_CHANNEL="stable"
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
SKIP_UPDATE=0
TOOLS_OUTPUT_DIR=""
DRYRUN=false
VERIFY_UPDATER_ARCHIVE="0"
IS_ROOT=false
if [ $EUID -eq 0 ]; then
    IS_ROOT=true
fi


set -o pipefail

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
            mkdir -p "${THISDIR}" >/dev/null
            pushd "${THISDIR}" >/dev/null
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
        -s)
            SKIP_UPDATE=1
            ;;
        -gettools)
            shift
            TOOLS_OUTPUT_DIR=$1
            ;;
        -verify)
            shift
            VERIFY_UPDATER_ARCHIVE="1"
            ;;
        -z)
            DRYRUN=true
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
if [ ${RESUME_INSTALL} -eq 0 ] && ! $DRYRUN; then
    if [ "${BINDIR}" = "" ]; then
        BINDIR="${SCRIPTPATH}"
    fi
fi

# If -d not specified, don't default any more
if [ "${#DATADIRS[@]}" -eq 0 ]; then
    echo "You must specify at least one data directory with \`-d\`"
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
    CURRENTVER="$(( ${BINDIR}/algod -v 2>/dev/null || echo 0 ) | head -n 1)"
    echo "Current Version = ${CURRENTVER}"
}

function get_updater_url() {
    local UNAME
    local OS
    local ARCH
    UNAME=$(uname)
    if [[ "${UNAME}" = "Darwin" ]]; then
        OS="darwin"
        UNAME=$(uname -m)
        if [[ "${UNAME}" = "x86_64" ]]; then
            ARCH="amd64"
        elif [[ "${UNAME}" = "arm64" ]]; then
            ARCH="arm64"
        else
            echo "This platform ${UNAME} is not supported by updater."
            exit 1
        fi
    elif [[ "${UNAME}" = "Linux" ]]; then
        OS="linux"
        UNAME=$(uname -m)
        if [[ "${UNAME}" = "x86_64" ]]; then
            ARCH="amd64"
        elif [[ "${UNAME}" = "aarch64" ]]; then
            ARCH="arm64"
        else
            echo "This platform ${UNAME} is not supported by updater."
            exit 1
        fi
    else
        echo "This operating system ${UNAME} is not supported by updater."
        exit 1
    fi

    # the updater will auto-update itself to the latest version, this means that the version of updater that is downloaded
    # can be arbitrary as long as the self-updating functionality is working, hence the hard-coded version
    UPDATER_FILENAME="install_${UPDATER_CHANNEL}_${OS}-${ARCH}_${UPDATER_MIN_VERSION}.tar.gz"
    UPDATER_URL="https://algorand-releases.s3.amazonaws.com/channel/${UPDATER_CHANNEL}/${UPDATER_FILENAME}"

    # also set variables for signature and checksum validation
    if [ "$VERIFY_UPDATER_ARCHIVE" = "1" ]; then
        UPDATER_PUBKEYURL="https://releases.algorand.com/key.pub"
        UPDATER_SIGURL="https://algorand-releases.s3.amazonaws.com/channel/${UPDATER_CHANNEL}/${UPDATER_FILENAME}.sig"
        UPDATER_CHECKSUMURL="https://algorand-releases.s3.amazonaws.com/channel/${UPDATER_CHANNEL}/hashes_${UPDATER_CHANNEL}_${OS}_${ARCH}_${UPDATER_MIN_VERSION}"
    fi
}

# check to see if the binary updater exists. if not, it will automatically the correct updater binary for the current platform
function check_for_updater() {
    # check if the updater binary exist and is not empty.
    if [[ -s "${SCRIPTPATH}/updater" && -f "${SCRIPTPATH}/updater" ]]; then
        return 0
    fi

    # set UPDATER_URL and UPDATER_ARCHIVE as a global that can be referenced here
    # UPDATER_PUBKEYURL, UPDATER_SIGURL, UPDATER_CHECKSUMURL will be set to try verification
    get_updater_url

    # check if curl is available
    if ! type curl &>/dev/null; then
        # no curl is installed.
        echo "updater binary is missing and cannot be downloaded since curl is missing."
        echo "To install curl, run the following command:"
        echo "On Linux: apt-get update; apt-get install -y curl"
        echo "On Mac: brew install curl"
        exit 1
    fi

    # create temporary directory for updater archive
    local UPDATER_TEMPDIR="" UPDATER_ARCHIVE=""
    UPDATER_TEMPDIR="$(mktemp -d 2>/dev/null || mktemp -d -t "tmp")"
    UPDATER_ARCHIVE="${UPDATER_TEMPDIR}/${UPDATER_FILENAME}"

    # download updater archive
    echo "Downloading $UPDATER_URL"
    if ! curl -sSL "$UPDATER_URL" -o "$UPDATER_ARCHIVE"; then
        echo "failed to download updater archive from ${UPDATER_URL} using curl."
        exit 1
    fi

    if [ ! -f "$UPDATER_ARCHIVE" ]; then
        echo "downloaded file ${UPDATER_ARCHIVE} is missing."
        exit
    else
        echo "Downloaded into file ${UPDATER_ARCHIVE}"
    fi

    # if -verify command line flag is set, try verifying updater archive
    if [ "$VERIFY_UPDATER_ARCHIVE" = "1" ]; then
        echo "Starting to verify the updater archive"
        # check for checksum and signature validation dependencies
        local GPG_VERIFY="0" CHECKSUM_VERIFY="0"
        if type gpg >&/dev/null; then
            GPG_VERIFY="1"
        else
            echo "gpg is not available to perform signature validation."
        fi

        if type sha256sum &>/dev/null; then
            CHECKSUM_VERIFY="1"
        else
            echo "sha256sum is not available to perform checksum validation."
        fi

        # try signature validation
        if [ "$GPG_VERIFY" = "1" ]; then
            local UPDATER_SIGFILE="$UPDATER_TEMPDIR/updater.sig" UPDATER_PUBKEYFILE="$UPDATER_TEMPDIR/key.pub"
            # try downloading public key
            if curl -sSL "$UPDATER_PUBKEYURL" -o "$UPDATER_PUBKEYFILE"; then
                GNUPGHOME="$(mktemp -d)"; export GNUPGHOME
                if gpg --import "$UPDATER_PUBKEYFILE"; then
                    if curl -sSL "$UPDATER_SIGURL" -o "$UPDATER_SIGFILE"; then
                        if ! gpg --verify "$UPDATER_SIGFILE" "$UPDATER_ARCHIVE"; then
                            echo "failed to verify signature of updater archive."
                            exit 1
                        else
                            echo "Verified signature of updater archive"
                        fi
                    else
                        echo "failed download signature file, cannot perform signature validation."
                    fi
                else
                    echo "failed importing GPG public key, cannot perform signature validation."
                fi
                # clean up temporary directory used for signature validation
                rm -rf "$GNUPGHOME"; unset GNUPGHOME
            else
                echo "failed downloading GPG public key, cannot perform signature validation."
            fi
        fi

        # try checksum validation
        if [ "$CHECKSUM_VERIFY" = "1" ]; then
            local UPDATER_CHECKSUMFILE="$UPDATER_TEMPDIR/updater.checksum"
            # try downloading checksum file
            if curl -sSL "$UPDATER_CHECKSUMURL" -o "$UPDATER_CHECKSUMFILE"; then
                # have to be in same directory as archive
                pushd "$UPDATER_TEMPDIR"
                if ! sha256sum --quiet --ignore-missing -c "$UPDATER_CHECKSUMFILE"; then
                    echo "failed to verify checksum of updater archive."
                    popd
                    exit 1
                else
                    echo "Verified checksum of updater archive"
                fi
                popd
            else
                echo "failed downloading checksum file, cannot perform checksum validation."
            fi
        fi
    fi

    # extract and install updater
    if ! tar -zxf "$UPDATER_ARCHIVE" -C "$UPDATER_TEMPDIR" updater; then
        echo "failed to extract updater binary from ${UPDATER_ARCHIVE}"
        exit 1
    else
        mv "${UPDATER_TEMPDIR}/updater" "$SCRIPTPATH"
    fi

    # clean up temp directory
    rm -rf "$UPDATER_TEMPDIR"
    echo "updater binary was installed at ${SCRIPTPATH}/updater"
}

function check_for_update() {
    determine_current_version
    check_for_updater
    LATEST="$(${SCRIPTPATH}/updater ver check -c ${CHANNEL} ${BUCKET} | tail -1)"
    if [ $? -ne 0 ]; then
        echo "No remote updates found"
        return 1
    fi

    if [ -z ${LATEST} ]; then
        echo "Failed to lookup latest release"
        return 1
    fi

    echo "Latest Version = ${LATEST}"

    if [ ${CURRENTVER} -ge ${LATEST} ]; then
        if [ "${UPDATETYPE}" = "install" ]; then
            echo "No new version found - forcing install anyway"
        else
            echo "No new version found"
            return 1
        fi
    fi

    echo "New version found"
    return 0
}

function download_tools_update() {
    local TOOLS_SPECIFIC_VERSION=$1
    echo "downloading tools update ${TOOLS_SPECIFIC_VERSION}"
    TOOLS_TEMPDIR=$(mktemp -d 2>/dev/null || mktemp -d -t "tmp")
    export TOOLS_CLEANUP_UPDATE_TEMP_DIR=${TOOLS_TEMPDIR}
    trap "rm -rf ${TOOLS_CLEANUP_UPDATE_TEMP_DIR}" 0

    TOOLS_TARFILE=${TOOLS_TEMPDIR}/${LATEST}.tar.gz

    if ( ! "${SCRIPTPATH}"/updater gettools -c "${CHANNEL}" -o "${TOOLS_TARFILE}" "${BUCKET}" "${TOOLS_SPECIFIC_VERSION}" ) ; then
        echo "Error downloading tools tarfile"
        exit 1
    fi
    echo "Tools tarfile downloaded to ${TOOLS_TARFILE}"

    mkdir -p "${TOOLS_OUTPUT_DIR}"
    if ( ! tar -xf "${TOOLS_TARFILE}" -C "${TOOLS_OUTPUT_DIR}" ) ; then
        echo "Error extracting the tools update file ${TOOLS_TARFILE}"
        exit 1
    fi
    echo "Tools extracted to ${TOOLS_OUTPUT_DIR}"
}

TEMPDIR=""
TARFILE=""
UPDATESRCDIR=""

function download_update() {
    SPECIFIC_VERSION=$1

    if [ -n "${TOOLS_OUTPUT_DIR}" ]; then
        download_tools_update "${SPECIFIC_VERSION}"
    fi

    TEMPDIR=$(mktemp -d 2>/dev/null || mktemp -d -t "tmp")
    export CLEANUP_UPDATE_TEMP_DIR=${TEMPDIR}
    trap "rm -rf ${CLEANUP_UPDATE_TEMP_DIR}" 0

    TARFILE=${TEMPDIR}/${LATEST}.tar.gz
    UPDATESRCDIR=${TEMPDIR}/a
    mkdir ${UPDATESRCDIR}

    ${SCRIPTPATH}/updater ver get -c ${CHANNEL} -o ${TARFILE} ${BUCKET} ${SPECIFIC_VERSION}

    if [ $? -ne 0 ]; then
        echo "Error downloading update file"
        exit 1
    fi
    echo "Update Downloaded to ${TARFILE}"
}

function check_and_download_update() {
    if ! check_for_update; then
        return 1
    fi

    download_update
}

function download_update_for_current_version() {
    determine_current_version
    echo "Downloading update package for current version ${CURRENTVER}..."
    download_update "-v ${CURRENTVER}"
}

function expand_update() {
    echo "Expanding update..."
    if ! tar -zxof "${TARFILE}" -C "${UPDATESRCDIR}"; then
        return 1
    fi
    validate_update
}

function validate_update() {
    echo "Validating update..."
    # We should consider including a version.info file
    # that we can compare against the expected version
    return 0
}

function check_service() {
    local service_type="$1"
    local dd="$2"
    local path

    if [ "$service_type" = "user" ]; then
        path=$(awk -F= '{ print $2 }' <(systemctl --user show -p FragmentPath "algorand@$(systemd-escape "$dd")"))
    else
        path=$(awk -F= '{ print $2 }' <(systemctl show -p FragmentPath "algorand@$(systemd-escape "$dd")"))
    fi

    if [ "$path" != "" ]; then
        return 0
    fi

    return 1
}

function run_systemd_action() {
    if [ "$(uname)" = "Darwin" ]; then
        return 1
    fi

    local action=$1
    local data_dir=$2
    local process_owner

    # If the service is system-level, check if it's root or sudo
    if check_service system "$data_dir"; then
        process_owner=$(awk '{ print $1 }' <(ps aux | grep "[a]lgod -d ${data_dir}"))
        if $IS_ROOT; then
            if systemctl "$action" "algorand@$(systemd-escape "$data_dir")"; then
                echo "systemd system service: $action"
                return 0
            fi
        elif grep sudo <(groups "$process_owner") &> /dev/null; then
            if sudo -n systemctl "$action" "algorand@$(systemd-escape "$data_dir")"; then
                echo "sudo -n systemd system service: $action"
                return 0
            fi
        fi

    # If the service is user-level then run systemctl --user
    elif check_service user "$data_dir"; then
        if systemctl --user "$action" "algorand@$(systemd-escape "${data_dir}")"; then
            echo "systemd user service: $action"
            return 0
        fi
    fi

    return 1
}

function backup_binaries() {
    echo "Backing up current binary files..."
    mkdir -p "${BINDIR}/backup"
    BACKUPFILES="algod kmd carpenter doberman goal update.sh updater diagcfg"
    # add node_exporter to the files list we're going to backup, but only we if had it previously deployed.
    [ -f "${BINDIR}/node_exporter" ] && BACKUPFILES="${BACKUPFILES} node_exporter"
    # If we have algotmpl, we should back it up too
    [ -f "${BINDIR}/algotmpl" ] && BACKUPFILES="${BACKUPFILES} algotmpl"
    tar -zcf "${BINDIR}/backup/bin-v${CURRENTVER}.tar.gz" -C "${BINDIR}" ${BACKUPFILES} >/dev/null 2>&1
}

function backup_data() {
    CURDATADIR=$1
    BACKUPDIR="${CURDATADIR}/backup"

    echo "Backing up current data files from ${CURDATADIR}..."
    mkdir -p "${BACKUPDIR}"
    BACKUPFILES="genesis.json wallet-genesis.id"
    tar --no-recursion --exclude='*.log' --exclude='*.log.archive' --exclude='*.tar.gz' -zcf "${BACKUPDIR}/data-v${CURRENTVER}.tar.gz" -C "${CURDATADIR}" ${BACKUPFILES} >/dev/null 2>&1
}

function backup_current_version() {
    backup_binaries
    for DD in ${DATADIRS[@]}; do
        backup_data "${DD}"
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
        echo "Installing new binary files into ${BINDIR}"
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
            echo "Installed genesis account file: ${file}"
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
        cp "${UPDATESRCDIR}/data/"* "${CURDATADIR}"
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
        echo "Auto-start node disabled - not starting"
        return
    fi

    CURDATADIR=$1
    echo "Restarting node in ${CURDATADIR}..."

    check_install_valid
    if [ $? -ne 0 ]; then
        fail_and_exit "Installation does not appear to be valid"
    fi

    if ! run_systemd_action restart "${CURDATADIR}"; then
        echo "No systemd services, restarting node with goal."
        ${BINDIR}/goal node restart -d "${CURDATADIR}" ${HOSTEDFLAG}
    fi
}

function startup_nodes() {
    for DD in ${DATADIRS[@]}; do
        startup_node ${DD}
    done
}

function rollback() {
    echo "Rolling back from failed update..."
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
    rm "${BINDIR}/algorand" >/dev/null 2>&1

    for DD in ${DATADIRS[@]}; do
        clean_legacy_logs "${DD}"

        # Purge obsolete cadaver files (now agreement.cdv[.archive])
        rm -f "${DD}"/service*.cadaver
    done
}

#--------------------------------------------
# Main Update Driver

# Need to verify the bindir was specified (with -p)
# and that it's a valid directory.
# Unless it's an install
if [ ! -d "${BINDIR}" ]; then
    if [ "${UPDATETYPE}" = "install" ]; then
        mkdir -p "${BINDIR}"
    else
        fail_and_exit "Missing or invalid binaries path specified '${BINDIR}'"
    fi
fi

if [ "${UPDATETYPE}" != "install" ]; then
    if ! check_install_valid; then
        echo "Unable to perform an update - installation does not appear valid"
        exit 1
    fi
fi

# If we're initiating an update/install, check for an update and if we have a new one,
# expand it and invoke the new update.sh script.
if [ ${RESUME_INSTALL} -eq 0 ] && ! $DRYRUN; then
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

    if ! expand_update; then
        fail_and_exit "Error expanding update"
    fi

    # Spawn the new update script and exit - this allows us to push update.sh changes that take effect immediately
    # Note that the SCRIPTPATH we're passing in should be our binaries directory, which is what we expect to be
    # passed as the last argument (if any)
    echo "Starting the new update script to complete the installation..."
    exec "${UPDATESRCDIR}/bin/${FILENAME}" ${INSTALLOPT} -r -c ${CHANNEL} ${DATADIRSPEC} ${NOSTART} ${BINDIRSPEC} ${HOSTEDSPEC} ${GENESIS_NETWORK_DIR_SPEC} ${UNKNOWNARGS[@]}

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

# Any fail_and_exit beyond this point will run a restart
RESTART_NODE=1

if ! $DRYRUN; then
    if [ ${SKIP_UPDATE} -eq 0 ]; then
        backup_current_version
    fi

    # We don't care about return code - doesn't matter if we failed to archive

    ROLLBACK=1

    if ! install_new_binaries; then
        fail_and_exit "Error installing new files"
    fi

    for DD in ${DATADIRS[@]}; do
        if ! install_new_data "${DD}"; then
            fail_and_exit "Error installing data files into ${DD}"
        fi
    done

    copy_genesis_files

    for DD in ${DATADIRS[@]}; do
        if ! check_for_new_ledger "${DD}"; then
            fail_and_exit "Error updating ledger in ${DD}"
        fi
    done

    if [ "${TESTROLLBACK}" != "" ]; then
        fail_and_exit "Simulating update failure - rolling back"
    fi

    apply_fixups
fi

if [ "${NOSTART}" != "" ]; then
    echo "Install complete - restart node manually"
else
    startup_nodes
fi

exit 0
