#!/usr/bin/env bash
# shellcheck disable=2164

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

apt-get update -y
# Install the awscli using the python installer to work around the uploading
# zero length files issue. See https://github.com/aws/aws-cli/issues/2403
apt-get install jq python-pip -y
pip install awscli
ln -s /usr/local/bin/aws /usr/bin/aws

if [ ! -f "$SCRIPTPATH/service_env.sh" ]; then
  cp -p "$SCRIPTPATH/env.sh" "$SCRIPTPATH/service_env.sh"
fi

cp "$SCRIPTPATH/buildhost.service" /etc/systemd/system/

echo -e "WorkingDirectory=$SCRIPTPATH\nExecStart=/bin/bash $SCRIPTPATH/run.sh\nEnvironmentFile=$SCRIPTPATH/service_env.sh" >> /etc/systemd/system/buildhost.service

systemctl enable buildhost
echo "Installation complete. Please edit the service_env.sh file and start the service:"
echo "nano $SCRIPTPATH/service_env.sh"
echo "systemctl start buildhost"

