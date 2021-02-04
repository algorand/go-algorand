#!/bin/bash

# To test: `./test_update.sh`

set -e

BINDIR=.
DATADIR=

while getopts "b:d:" opt
do
    case "$opt" in
        b)
            BINDIR="$OPTARG"
            ;;
        d)
            DATADIR="$OPTARG"
            ;;
        *)
            echo "Unrecognized option"
            exit 1
            ;;
    esac
done

if [ -z "$DATADIR" ]
then
    if ! USERLINE=$(getent passwd "$USER"); then
        echo "[ERROR] \`$USER\' not found on system. Aborting..."
        exit 1
    else
        HOMEDIR=$(awk -F: '{ print $6 }' <<< "$USERLINE")
        DATADIR="$HOMEDIR/node/data"
    fi
fi

NODE_STOPPED="The node was successfully stopped."
NODE_STARTED="Algorand node successfully started!"
NODE_STARTED_GOAL="No systemd services, starting node with goal."

# Start the node manually so we can test that the node was first shut down.
"$BINDIR/goal" node start -d "$DATADIR"

echo
echo "------------------------------------------------------------------"
echo

echo "Testing starting and stopping node, no systemd services installed..."

LOGS=$(./update.sh -i -c stable -z -p "$BINDIR" -d "$DATADIR" 2> /dev/null)

if [[ ! "$LOGS" =~ $NODE_STOPPED ]]
then
    echo "[ERROR] The node was not stopped."
    exit 1
fi

if [[ ! "$LOGS" =~ $NODE_STARTED ]]
then
    echo "[ERROR] The node was not started."
    exit 1
fi

if [[ ! "$LOGS" =~ $NODE_STARTED_GOAL ]]
then
    echo "[ERROR] The node was not started with goal."
    exit 1
fi

echo "Tests passed."

echo
echo "------------------------------------------------------------------"
echo

echo "Testing starting and stopping node, systemd system service installed..."

sudo "$BINDIR/systemd-setup.sh" "$USER" "$USER"

NODE_STOPPED="systemd system service: stop"
NODE_STARTED="systemd system service: start"

LOGS=$(sudo "$BINDIR/update.sh" -i -c stable -z -p "$BINDIR" -d "$DATADIR" 2> /dev/null)

if [[ ! "$LOGS" =~ $NODE_STOPPED ]]
then
    echo "[ERROR] The node was not stopped."
    exit 1
fi

if [[ ! "$LOGS" =~ $NODE_STARTED ]]
then
    echo "[ERROR] The node was not started."
    exit 1
fi

echo "Tests passed."
echo
echo "Cleaning up."

sudo systemctl stop "algorand@$(systemd-escape "$DATADIR")"
sudo rm -f /lib/systemd/system/algorand@.service
sudo systemctl daemon-reload

# Start the node manually so we can test that the node was first shut down.
"$BINDIR/goal" node start -d "$DATADIR"

echo
echo "------------------------------------------------------------------"
echo

echo "Testing starting and stopping node, systemd user service installed..."

"$BINDIR/systemd-setup-user.sh" "$USER"

NODE_STOPPED="systemd user service: stop"
NODE_STARTED="systemd user service: start"

LOGS=$("$BINDIR/update.sh" -i -c stable -z -p "$BINDIR" -d "$DATADIR" 2> /dev/null)

if [[ ! "$LOGS" =~ $NODE_STOPPED ]]
then
    echo "[ERROR] The node was not stopped."
    exit 1
fi

if [[ ! "$LOGS" =~ $NODE_STARTED ]]
then
    echo "[ERROR] The node was not started."
    exit 1
fi

echo "Tests passed."
echo
echo "Cleaning up."

systemctl --user stop "algorand@$(systemd-escape "$DATADIR")"
rm -f "$HOMEDIR/.config/systemd/user/algorand@.service"
systemctl --user daemon-reload

