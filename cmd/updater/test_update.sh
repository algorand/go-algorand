#!/bin/bash

#set -e

DATADIR=data

if ! USERLINE=$(getent passwd "$USER"); then
    echo "[ERROR] \`$USER\' not found on system. Aborting..."
    exit 1
else
    HOMEDIR=$(awk -F: '{ print $6 }' <<< "$USERLINE")
    DATADIR="$HOMEDIR/node/data"
fi

NODE_STOPPED="The node was successfully stopped."
NODE_STARTED="Algorand node successfully started!"
NODE_STARTED_GOAL="No systemd services, starting node with goal."

# Start the node manually so we can test that the node was first shut down.
./goal node start -d "$DATADIR"

echo
echo "-----------------------------------------------"
echo

echo "Testing starting and stopping node, no systemd services installed..."

logs=$(./update.sh -i -c stable -r -z -p ../node -d "$DATADIR" 2> /dev/null)

if [[ ! "$logs" =~ $NODE_STOPPED ]]
then
    echo "[ERROR] The node was not stopped."
    exit 1
fi

if [[ ! "$logs" =~ $NODE_STARTED ]]
then
    echo "[ERROR] The node was not started."
    exit 1
fi

if [[ ! "$logs" =~ $NODE_STARTED_GOAL ]]
then
    echo "[ERROR] The node was not started with goal."
    exit 1
fi

echo "Tests passed."

echo
echo "-----------------------------------------------"
echo

echo "Testing starting and stopping node, systemd system service installed..."

sudo ./systemd-setup.sh btoll btoll

NODE_STOPPED="systemd system service: stop"
NODE_STARTED="systemd system service: start"

logs=$(sudo ./update.sh -i -c stable -r -z -p ../node -d "$DATADIR" 2> /dev/null)

if [[ ! "$logs" =~ $NODE_STOPPED ]]
then
    echo "[ERROR] The node was not stopped."
    exit 1
fi

if [[ ! "$logs" =~ $NODE_STARTED ]]
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
./goal node start -d "$DATADIR"

echo
echo "-----------------------------------------------"
echo

echo "Testing starting and stopping node, systemd user service installed..."

./systemd-setup.sh btoll --user

NODE_STOPPED="systemd user service: stop"
NODE_STARTED="systemd user service: start"

logs=$(./update.sh -i -c stable -r -z -p ../node -d "$DATADIR" 2> /dev/null)

if [[ ! "$logs" =~ $NODE_STOPPED ]]
then
    echo "[ERROR] The node was not stopped."
    exit 1
fi

if [[ ! "$logs" =~ $NODE_STARTED ]]
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

