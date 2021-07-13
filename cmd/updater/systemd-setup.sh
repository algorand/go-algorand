#!/bin/bash
# shellcheck disable=2086
#
# Run this script to set up the systemd system service for algod.
# The arguments are the username and groupname that algod should run as.

set -e

setup_root() {
    local sedargs="-e s,@@USER@@,$1, -e s,@@GROUP@@,$2, -e s,@@BINDIR@@,$3,"
    sed ${sedargs} "${SCRIPTPATH}/sudoers.template" \
        > /etc/sudoers.d/99-algo-systemctl

    sed ${sedargs} "${SCRIPTPATH}/algorand@.service.template" \
        > /lib/systemd/system/algorand@.service

    systemctl daemon-reload
}

if [ "$#" != 2 ] && [ "$#" != 3 ]; then
    echo "Usage: $0 username group [bindir]"
    exit 1
fi

SCRIPTPATH="$( cd "$(dirname "$0")" ; pwd -P )"
USER="$1"
GROUP="$2"
BINDIR="$3"

if [ -z "$BINDIR" ]; then
    echo "[INFO] BINDIR is unset, setting to cwd."
    BINDIR=$(pwd)
fi

if ! id -u "${USER}"> /dev/null; then
    echo "$0 [ERROR] Username \`$USER\` does not exist on system"
    exit 1
fi

setup_root "${USER}" "${GROUP}" "${BINDIR}"
echo "[SUCCESS] systemd system service has been installed."

