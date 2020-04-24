#!/usr/bin/env bash

set -ex

# Path is relative to the root of the Jenkins workspace.
cd scripts/release/prod/generate_releases_page
./generate_releases_page > index.html
aws s3 cp index.html s3://algorand-releases

