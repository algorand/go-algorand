#!/bin/bash
#
# Test a systemd user service.
# ./test_systemd-setup.sh -u $USER -g --user
#
# Test a systemd system service.
# sudo ./test_systemd-setup.sh -u $USER -g $USER
#

trap cleanup err exit

cleanup() {
    rm -f "$SERVICE"
}

BINDIR=.
DATADIR=
GROUPNAME=
USERNAME=

while getopts "b:d:g:u:" opt
do
    case "$opt" in
        b)
            BINDIR="$OPTARG"
            ;;
        d)
            DATADIR="$OPTARG"
            ;;
        g)
            GROUPNAME="$OPTARG"
            ;;
        u)
            USERNAME="$OPTARG"
            ;;
        *)
            echo "Unrecognized option"
            exit 1
            ;;
    esac
done

if [ -z "$GROUPNAME" ] || [ -z "$USERNAME" ]
then
    echo "[ERROR] GROUPNAME=$GROUPNAME and USERNAME=$USERNAME are required parameters."
    exit 1
fi

if [ -z "$DATADIR" ]
then
    if ! USERLINE=$(getent passwd "$USERNAME"); then
        echo "[ERROR] \`$USER\' not found on system. Aborting..."
        exit 1
    else
        HOMEDIR=$(awk -F: '{ print $6 }' <<< "$USERLINE")
        DATADIR="$HOMEDIR/node/data"
    fi
fi

SYSTEM_SERVICE=/lib/systemd/system/algorand@.service
SERVICE="$SYSTEM_SERVICE"
IS_USER=false

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

run_systemd_action() {
    local action="$1"

    if $IS_USER; then
        systemctl --user "$action" algorand@"$(systemd-escape "$DATADIR")"
    else
        systemctl "$action" algorand@"$(systemd-escape "$DATADIR")"
    fi
}

stop_service() {
    if $IS_USER; then
        systemctl --user stop algorand@"$(systemd-escape "$DATADIR")"
    else
        systemctl stop algorand@"$(systemd-escape "$DATADIR")"
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
        systemctl --user status algorand@"$(systemd-escape "$DATADIR")" > /dev/null
    else
        systemctl status algorand@"$(systemd-escape "$DATADIR")" > /dev/null
    fi
    # To stdout:
    #   Exit code=1
    #   Failed to connect to bus: No such file or directory
    #
    #   Exit code=4
    #   Unit algorand@-home-kilgoretrout-node-data.service could not be found.
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
        status=$(systemctl --user status algorand@"$(systemd-escape "$DATADIR")")
    else
        status=$(systemctl status algorand@"$(systemd-escape "$DATADIR")")
    fi

    active_status="$(awk '/Active/ { print $2 }' <<< "$status")"
    if [ "$active" != "$active_status" ]; then
        echo "The Active status \`$active_status\` does not equal the expected status \`$active\`"
        exit 1
    fi
}

"$BINDIR/systemd-setup.sh" "$USERNAME" "$GROUPNAME"

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
    run_systemd_action start
    verify_service_status $IS_USER active
    echo Service has been started.

    echo Stop the service...
    run_systemd_action stop
    verify_service_status $IS_USER inactive
    echo Service has been stopped.
else
    echo Could not write service to disk.
    exit 1
fi

