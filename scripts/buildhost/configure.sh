#!/usr/bin/env bash

# configure.sh - Configure a new EC2 machine as a buildhost
#
# Syntax:   configure.sh
#
# Usage:    Should only be used when deploying a new build host.
#
# Examples: scripts/buildhost/configure.sh
#


if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi


SCRIPTPATH="$( cd "$(dirname "$0")" ; pwd -P )"

sudo apt-get update -y
sudo apt-get install jq -y

# install the awscli using the python installer to work around
# the uploading zero length files issue. see https://github.com/aws/aws-cli/issues/2403
sudo apt install python-pip -y
sudo pip install awscli
sudo ln -s /usr/local/bin/aws /usr/bin/aws

if [ ! -f ${SCRIPTPATH}/service_env.sh ]; then
  cp -p ${SCRIPTPATH}/env.sh ${SCRIPTPATH}/service_env.sh
fi
sudo cp ${SCRIPTPATH}/buildhost.service /etc/systemd/system/
sudo echo "WorkingDirectory=${SCRIPTPATH}" >> /etc/systemd/system/buildhost.service
sudo echo "ExecStart=/bin/bash ${SCRIPTPATH}/run.sh" >> /etc/systemd/system/buildhost.service
sudo echo "EnvironmentFile=${SCRIPTPATH}/service_env.sh" >> /etc/systemd/system/buildhost.service

sudo systemctl enable buildhost
echo "Installation complete. Please edit the service_env.sh file and start the service:"
echo "nano ${SCRIPTPATH}/service_env.sh"
echo "sudo systemctl start buildhost"



