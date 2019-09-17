#!/usr/bin/env bash

if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi


SCRIPTPATH="$( cd "$(dirname "$0")" ; pwd -P )"

sudo apt-get update -y
sudo apt-get install awscli -y
sudo apt-get install jq -y


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



