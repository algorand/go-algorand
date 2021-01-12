#!/bin/bash

set -e

trap cleanup err exit

cleanup() {
    echo "Cleaning up..."
    if $IS_SYSTEM_SERVICE
    then
        sudo -n systemctl stop "algorand@$(systemd-escape "$DATADIR")"
        sudo -n rm -f /lib/systemd/system/algorand@.service
        sudo -n systemctl daemon-reload
    elif $IS_USER_SERVICE
    then
        systemctl --user stop "algorand@$(systemd-escape "$DATADIR")"
        rm -f "$HOMEDIR/.config/systemd/user/algorand@.service"
        systemctl --user daemon-reload
    fi

    if $IS_ROOT
    then
        sudo -n ./goal node stop -d "$DATADIR"
    else
        ./goal node stop -d "$DATADIR"
    fi
}

DATADIR=data
IS_ROOT=false
IS_SYSTEM_SERVICE=false
IS_USER_SERVICE=false

if ! USERLINE=$(getent passwd "$USER"); then
    echo "[ERROR] \`$USER\' not found on system. Aborting..."
    exit 1
else
    HOMEDIR=$(awk -F: '{ print $6 }' <<< "$USERLINE")
    DATADIR="$HOMEDIR/node/data"
fi

if [ "$EUID" -ne 0 ]
then
    IS_ROOT=true
fi

get_node_status() {
    ./goal node status -d "$DATADIR" > /dev/null
}

NODE_STOPPED="The node was successfully stopped."
NODE_STARTED="Algorand node successfully started!"
#NODE_STARTED_GOAL="No systemd services, starting node with goal."

#while read -r line
#do
#    echo "$line"
#    if [[ "$line" = "$NODE_STOPPED" ]]
#    then
#        if get_node_status
#        then
#            echo Node was not stopped.
#            exit 1
#        else
#            echo Node was stopped successfully.
#        fi
#    fi
#
#    if [[ "$line" = "$NODE_STARTED" ]]
#    then
#        if ! get_node_status
#        then
#            echo Node was not started.
#            exit 1
#        else
#            echo Node was started successfully.
#        fi
#    fi
#done < <(./update.sh -i -c stable -r -z -p ../node -d "$DATADIR" 2> /dev/null)

sudo -n ./systemd-setup.sh btoll btoll
IS_SYSTEM_SERVICE=true

NODE_STOPPED="systemd system service: stop"
NODE_STARTED="systemd system service: start"

while read -r line
do
    echo "$line"
    if [[ "$line" = "$NODE_STOPPED" ]]
    then
        if get_node_status
        then
            echo Node was not stopped.
            exit 1
        else
            echo Node was stopped successfully.
        fi
    fi

    if [[ "$line" = "$NODE_STARTED" ]]
    then
        if ! get_node_status
        then
            echo Node was not started.
            exit 1
        else
            echo Node was started successfully.
        fi
    fi
done < <(sudo -n ./update.sh -i -c stable -r -z -p ../node -d "$DATADIR" 2> /dev/null)

IS_SYSTEM_SERVICE=false
IS_USER_SERVICE=true

