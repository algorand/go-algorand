#!/usr/bin/env bash

set -ex

HERE=$(pwd)
pushd "$HOME/projects/releases-page"
./generate_releases_page.py > "$HERE/index.html"
popd

aws s3 cp index.html s3://algorand-staging/releases-page/
aws s3 cp s3://algorand-staging/releases-page/index.html s3://algorand-releases/

