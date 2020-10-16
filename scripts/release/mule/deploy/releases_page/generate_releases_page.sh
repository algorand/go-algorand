#!/usr/bin/env bash

set -ex

./generate_releases_page.py > index.html
aws s3 cp index.html s3://algorand-staging/releases-page/
aws s3 cp s3://algorand-staging/releases-page/index.html s3://algorand-releases/

