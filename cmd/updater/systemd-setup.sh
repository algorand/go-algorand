#!/bin/bash
# shellcheck disable=2086,2164
#
# Run this script to set up the systemd service for algod.
# The arguments are the username and groupname that algod should run as.
# If wanting to run as a user service, substitute "--user" for the groupname.

set -e

setup_user() {
    local user="$1"
    local userline

    if ! userline=$(getent passwd "$user"); then
        echo "[ERROR] \`$USER\' not found on system. Aborting..."
        exit 1
    else
        homedir=$(awk -F: '{ print $6 }' <<< "$userline")
    fi

    mkdir -p "$homedir/.config/systemd/user"
    cp "${SCRIPTPATH}/algorand@.service.template-user" \
        "$homedir/.config/systemd/user/algorand@.service"

    systemctl --user daemon-reload
}

setup_root() {
    local sedargs="-e s,@@USER@@,$1, -e s,@@GROUP@@,$2,"
    sed ${sedargs} "${SCRIPTPATH}/sudoers.template" \
        > /etc/sudoers.d/99-algo-systemctl

    sed ${sedargs} "${SCRIPTPATH}/algorand@.service.template" \
        > /lib/systemd/system/algorand@.service

    systemctl daemon-reload
}

SCRIPTPATH="$( cd "$(dirname "$0")" ; pwd -P )"

if [ "$#" != 2 ]; then
    echo "Usage: $0 username [group|--user]"
    exit 1
fi

USER="$1"

if ! id -u "${USER}"> /dev/null; then
    echo "$0 [ERROR] Username \`$USER\` does not exist on system"
    exit 1
fi

if [ "$2" = "--user" ]; then
    setup_user "${USER}"
else
    GROUP="$2"
    setup_root "${USER}" "${GROUP}"
fi


