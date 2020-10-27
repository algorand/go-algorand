#!/usr/bin/env bash

# Note: For this script to correctly pick up the new release, the new repo containing the new
#       packages MUST have been already pushed to S3! (See the deb deployment mule step.)
#
# 1. Generate the new releases page from the contents of `algorand-dev-deb-repo/releases/CHANNEL`.
# 2. Backup up the current releases page (index.html).
# 3. Copy the new index.html to staging.
# 4. Copy the new index.html to `algorand-releases`.

set -ex

./generate_releases_page.py > index.html
aws s3 cp s3://algorand-releases/index.html s3://algorand-staging/releases-page/index.html-previous
aws s3 cp index.html s3://algorand-staging/releases-page/
aws s3 cp index.html s3://algorand-releases/

