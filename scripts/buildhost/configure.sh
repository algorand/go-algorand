#!/usr/bin/env bash

if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

sudo apt-get update -y
sudo apt-get install awscli -y
sudo apt-get install pq -y


cp env.sh service_env.sh
sudo cp ./buildhost.service /etc/systemd/system/
WD=$(pwd)
sudo echo "WorkingDirectory=${WD}" >> /etc/systemd/system/buildhost.service
sudo echo "ExecStart=/bin/bash ./run.sh" >> /etc/systemd/system/buildhost.service
sudo echo "EnvironmentFile=${WD}/service_env.sh" >> /etc/systemd/system/buildhost.service

systemctl enable buildhost
systemctl start buildhost



