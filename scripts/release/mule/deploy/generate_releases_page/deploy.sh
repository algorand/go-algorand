#!/usr/bin/env bash

set -ex

WORKDIR="$5"

if [ -z "$WORKDIR" ]
then
    echo "WORKDIR variable must be defined."
    exit 1
fi

pushd "$WORKDIR/scripts/release/mule/deploy/generate_releases_page"
./generate_releases_page.py >| /tmp/index.html
popd
mule -f package-deploy.yaml package-deploy-releases-page

