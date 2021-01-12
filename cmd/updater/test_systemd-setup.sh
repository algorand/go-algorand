#!/bin/bash

if [ "$#" != 2 ]; then
  echo "Usage: $0 username [group|--user]"
  exit 1
fi

trap cleanup err exit

USERNAME="$1"
GROUPNAME="$2"
SYSTEM_SERVICE=/lib/systemd/system/algorand@.service
SERVICE="$SYSTEM_SERVICE"
IS_USER=false

cleanup() {
    rm -f "$SERVICE"
}

get_homedir() {
    local user="$1"
    local userline

    if ! userline=$(getent passwd "$user"); then
        echo "[ERROR] \`$USER\' not found on system. Aborting..."
        exit 1
    else
        homedir=$(awk -F: '{ print $6 }' <<< "$userline")
        echo "$homedir"
    fi
}

start_service() {
    if $IS_USER; then
        systemctl --user start algorand@"$(systemd-escape /home/btoll/node/data)"
    else
        systemctl start algorand@"$(systemd-escape /home/btoll/node/data)"
    fi
}

stop_service() {
    if $IS_USER; then
        systemctl --user stop algorand@"$(systemd-escape /home/btoll/node/data)"
    else
        systemctl stop algorand@"$(systemd-escape /home/btoll/node/data)"
    fi
}

verify_service_config() {
    # User services don't include "User" and "Group" lines in the "[Service]"
    # block so only do the following checks for a system service.
    if ! $IS_USER; then
        SERVICE_USERNAME=$(awk -F= '/User/ { print $2 }' "$SERVICE")
        if [ "$USERNAME" != "$SERVICE_USERNAME" ]; then
            echo bad username
            exit 1
        fi

        SERVICE_GROUPNAME=$(awk -F= '/Group/ { print $2 }' "$SERVICE")
        if [ "$GROUPNAME" != "$SERVICE_GROUPNAME" ]; then
            echo bad groupname
            exit 1
        fi
    fi
}

verify_service_not_installed() {
    # If a user service was installed verify that a system service was
    # not installed and vice-versa.
    echo Verify that a service was not installed.
    if $IS_USER; then
        systemctl --user status algorand@"$(systemd-escape /home/btoll/node/data)" > /dev/null
    else
        systemctl status algorand@"$(systemd-escape /home/btoll/node/data)" > /dev/null
    fi
    # To stdout:
    #   Exit code=1
    #   Failed to connect to bus: No such file or directory
    #
    #   Exit code=4
    #   Unit algorand@-home-btoll-node-data.service could not be found.
    EXIT_CODE="$?"
    if [ "$EXIT_CODE" -eq 1 ] || [ "$EXIT_CODE" -eq 4 ]; then
        echo An incorrect service was installed, aborting...
        exit 1
    fi
}

verify_service_status() {
    local is_user=$1
    local active="$2"
    local status
    local active_status

    if $is_user; then
        status=$(systemctl --user status algorand@"$(systemd-escape /home/btoll/node/data)")
    else
        status=$(systemctl status algorand@"$(systemd-escape /home/btoll/node/data)")
    fi

    active_status="$(awk '/Active/ { print $2 }' <<< "$status")"
    if [ "$active" != "$active_status" ]; then
        echo "The Active status \`$active_status\` does not equal the expected status \`$active\`"
        exit 1
    fi
}

./systemd-setup.sh "$USERNAME" "$GROUPNAME"

if [ "$GROUPNAME" = --user ]; then
    IS_USER=true
    HOMEDIR=$(get_homedir "$USERNAME")
    SERVICE="$HOMEDIR/.config/systemd/user/algorand@.service"
fi

if [ -f "$SERVICE" ]; then
    echo "Created service $SERVICE"

    verify_service_config
    verify_service_not_installed

    echo Verify the service was created but has not been started.
    verify_service_status $IS_USER inactive

    echo Start the service...
    start_service
    verify_service_status $IS_USER active
    echo Service has been started.

    echo Stop the service...
    stop_service
    verify_service_status $IS_USER inactive
    echo Service has been stopped.
else
    echo Could not write service to disk.
    exit 1
fi

