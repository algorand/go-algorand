#!/bin/bash
# shellcheck disable=2086,2164
#
# Run this script to set up the systemd service for algod.
# The arguments are the username and groupname that algod should run as.
# If wanting to run as a user service, substitute "--user" for the groupname.

setup_user() {
    mkdir -p "/home/$1/.config/systemd/user"
    cp "${SCRIPTPATH}/algorand@.service.template-user" \
        "/home/$1/.config/systemd/user/algorand@.service"

    systemctl --user daemon-reload
}

setup_root() {
    sedargs="-e s,@@USER@@,$1, -e s,@@GROUP@@,$2,"
    sed ${sedargs} "${SCRIPTPATH}/sudoers.template" \
        > /etc/sudoers.d/99-algo-systemctl

    sed ${sedargs} "${SCRIPTPATH}/algorand@.service.template" \
        > /lib/systemd/system/algorand@.service

    systemctl daemon-reload
}

SCRIPTPATH="$( cd "$(dirname "$0")" ; pwd -P )"

if [ "$#" != 2 ]; then
    echo "Usage: $0 username groupname"
    exit 1
fi

USER="$1"

if ! id -u "${USER}"; then
    echo "$0 [ERROR] User \`$USER\` does not exist on system"
    exit 1
fi

if [ "$2" = "--user" ]; then
    setup_user "${USER}"
else
    GROUP="$2"
    setup_root "${USER}" "${GROUP}"
fi


