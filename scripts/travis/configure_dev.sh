#!/usr/bin/env bash

# keep script execution on errors
set +e

SCRIPTPATH="$( cd "$(dirname "$0")" ; pwd -P )"
OS=$("${SCRIPTPATH}/../ostype.sh")
ARCH=$("${SCRIPTPATH}/../archtype.sh")

if [[ "${OS}" == "linux" ]]; then
    if [[ "${ARCH}" == "arm64" ]]; then
        set -e
        sudo apt-get update -y
        sudo apt-get -y install sqlite3 python3-venv libffi-dev libssl-dev
    elif [[ "${ARCH}" == "arm" ]]; then
        sudo sh -c 'echo "CONF_SWAPSIZE=1024" > /etc/dphys-swapfile; dphys-swapfile setup; dphys-swapfile swapon'
        set -e
        sudo apt-get update -y
        sudo apt-get -y install sqlite3
    elif [[ "${ARCH}" == "amd64" ]]; then
        set -x
        sudo df -H
        echo "/etc/fstab : "
        sudo cat /etc/fstab
        # removes the last line which is
        # none /var/ramfs tmpfs defaults,size=768m,noatime 0 2

        sudo umount -l /var/ramfs
        sudo umount -l /dev/shm
        sudo sed '3d' /etc/fstab > fstab
        #sudo echo "none /var/ramfs tmpfs defaults,noatime,nosuid,nodev,size=256m,noatime,mode=0755 0 0" >> fstab
        sudo echo "tmpfs /tmp tmpfs rw,noatime,size=768m,noatime,mode=1777 0 0" >> fstab
        sudo cp fstab /etc/fstab
        sudo rm fstab
        sudo mount -a
        
        #sudo mv /tmp /old_tmp
        #sudo mkdir -p /tmp
        #sudo chmod 777 /tmp
        #sudo mount -t tmpfs -o rw,size=768M tmpfs /tmp
        #sudo cp -r /old_tmp/ /tmp
        
        echo "/etc/fstab (updated): "
        sudo cat /etc/fstab
        sudo df -H
    fi
elif [[ "${OS}" == "darwin" ]]; then
    # we don't want to upgrade boost if we already have it, as it will try to update
    # other components.
    brew update
    brew tap homebrew/cask
    brew pin boost || true
fi

"${SCRIPTPATH}/../configure_dev.sh"
exit $?
