#!/bin/bash
#
# Run this script to set up the systemd user service for algod.
# The argument is the username for whom systemd will install the service.

set -e

setup_user() {
    local user="$1"
    local bindir="$2"
    local userline

    if ! userline=$(getent passwd "$user"); then
        echo "[ERROR] \`$USER\' not found on system. Aborting..."
        exit 1
    else
        homedir=$(awk -F: '{ print $6 }' <<< "$userline")
    fi

    mkdir -p "$homedir/.config/systemd/user"
    sed -e s,@@BINDIR@@,"$bindir", "${SCRIPTPATH}/algorand@.service.template-user" \
        > "$homedir/.config/systemd/user/algorand@.service"

    if [[ ${HOSTMODE} == true ]]; then
	    echo "[INFO] Hosted mode - replacing algod with algoh"
	    sed -i 's/algod/algoh/g' "$homedir/.config/systemd/user/algorand@.service"
    fi

    systemctl --user daemon-reload
}

HOSTMODE=false
while getopts H opt; do
    case $opt in
	H)
	    HOSTMODE=true
	    ;;
	?)
	    echo "Invalid option: -${OPTARG}"
	    exit 1
	    ;;
    esac
done
shift $((OPTIND-1))

if [ "$#" != 1 ]; then
    echo "Usage: $0 username"
    exit 1
fi

SCRIPTPATH="$( cd "$(dirname "$0")" ; pwd -P )"
USER="$1"
BINDIR="$2"

if [ -z "$BINDIR" ]; then
    echo "[INFO] BINDIR is unset, setting to cwd."
    BINDIR=$(pwd)
fi

if ! id -u "${USER}"> /dev/null; then
    echo "$0 [ERROR] Username \`$USER\` does not exist on system"
    exit 1
fi

setup_user "${USER}" "${BINDIR}"
echo "[SUCCESS] systemd user service has been installed."

