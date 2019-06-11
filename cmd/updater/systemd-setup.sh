#!/bin/bash
#
# Run this script to set up the systemd service for algod.
# The arguments are the username and groupname that algod
# should run as.

if [ "$#" != 2 ]; then
  echo "Usage: $0 username groupname"
  exit 1
fi

USER="$1"
GROUP="$2"

SCRIPTPATH="$( cd "$(dirname "$0")" ; pwd -P )"
SEDARGS="-e s,@@USER@@,${USER}, -e s,@@GROUP@@,${GROUP},"

cat ${SCRIPTPATH}/sudoers.template \
  | sed ${SEDARGS} \
  > /etc/sudoers.d/99-algo-systemctl

cat ${SCRIPTPATH}/algorand@.service.template \
  | sed ${SEDARGS} \
  > /lib/systemd/system/algorand@.service

systemctl daemon-reload
