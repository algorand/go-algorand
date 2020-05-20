#!/usr/bin/env bash

set -exo pipefail

echo
date "+build_release begin DEPLOY stage %Y%m%d_%H%M%S"
echo

WORKDIR="$3"

if [ -z "$WORKDIR" ]
then
    echo "WORKDIR variable must be defined."
    exit 1
fi

#OS_TYPE="$1"
#ARCH_TYPE="$2"

#BRANCH=${BRANCH:-$(git rev-parse --abbrev-ref HEAD)}
#CHANNEL=${CHANNEL:-$("$WORKDIR/scripts/compute_branch_channel.sh" "$BRANCH")}
#PKG_DIR="$WORKDIR/tmp/node_pkgs/$OS_TYPE/$ARCH_TYPE"

mule -f package-deploy.yaml package-deploy-setup-generate-releases-page

echo
date "+build_release end DEPLOY stage %Y%m%d_%H%M%S"
echo

