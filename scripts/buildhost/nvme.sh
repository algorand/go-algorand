#!/usr/bin/env bash

# nvme.sh - Optimize the EC2 Instance to use nvme if that option is available.
#
# Syntax:   nvme.sh
#
# Usage:    Should only be used by buildhost
#
# Examples: scripts/buildhost/nvme.sh

DEVNAME=`realpath /dev/disk/by-id/nvme-Amazon_EC2_NVMe_Instance_Storage*|head -1`
if [ ! -b "${DEVNAME}" ]; then
    echo "No nvme device found"
    exit 1
fi
if `mount|grep -q "${DEVNAME}"`; then
    echo "Unable to mount device"
    exit 1
fi

sudo mkfs.ext4 "${DEVNAME}"
sudo mkdir /data0
sudo mount "${DEVNAME}" /data0
sudo bash -c "echo '${DEVNAME} /data0 ext4 defaults 0 1' >> /etc/fstab"
sudo mkdir /data0/ubuntu
sudo chown ubuntu:ubuntu /data0/ubuntu
rsync -a ~/ /data0/ubuntu/
cd $HOME
cd ..
HOMEP=`pwd -P`
# variable substitution happens in the shell before the sudo
sudo mv "${HOME}" "${HOME}.old"
sudo bash -c "cd ${HOMEP}; ln -s /data0/ubuntu ${USER}"

exit 0
