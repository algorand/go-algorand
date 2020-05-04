#!/usr/bin/env bash

set -ex

cd scripts/release/prod/generate_releases_page
./generate_releases_page >| index.html
aws s3 cp index.html s3://algorand-releases

