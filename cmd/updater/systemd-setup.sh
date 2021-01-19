#!/bin/bash
# shellcheck disable=2086
#
# Run this script to set up the systemd system service for algod.
# The arguments are the username and groupname that algod should run as.

set -e

setup_root() {
    local sedargs="-e s,@@USER@@,$1, -e s,@@GROUP@@,$2,"
    sed ${sedargs} "${SCRIPTPATH}/sudoers.template" \
        > /etc/sudoers.d/99-algo-systemctl

    sed ${sedargs} "${SCRIPTPATH}/algorand@.service.template" \
        > /lib/systemd/system/algorand@.service

    systemctl daemon-reload
}

if [ "$#" != 2 ]; then
    echo "Usage: $0 username group"
    exit 1
fi

SCRIPTPATH="$( cd "$(dirname "$0")" ; pwd -P )"
USER="$1"
GROUP="$2"

if ! id -u "${USER}"> /dev/null; then
    echo "$0 [ERROR] Username \`$USER\` does not exist on system"
    exit 1
fi

setup_root "${USER}" "${GROUP}"

