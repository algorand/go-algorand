#!/usr/bin/env bash

# 1. Sync the staging area to `algorand-dev-deb-repo/releases/CHANNEL`.
# 2. Generate the new releases page from the contents of `algorand-dev-deb-repo/releases/CHANNEL`.
# 3. Backup up the current releases page (index.html).
# 4. Copy the new index.html to staging.
# 5. Copy the new index.html to `algorand-releases`.

set -ex

if [ -z "$NETWORK" ] || [ -z "$VERSION" ]
then
    echo "[$0] Network and version are required parameters."
    exit 1
fi

CHANNEL=$(./scripts/release/mule/common/get_channel.sh "$NETWORK")

cd scripts/release/mule/deploy/releases_page

aws s3 sync --acl public-read "s3://algorand-staging/releases/$CHANNEL/$VERSION" "s3://algorand-dev-deb-repo/releases/$CHANNEL/$(./reverse_hex_timestamp)_$VERSION"
./generate_releases_page.py > index.html
aws s3 cp s3://algorand-releases/index.html s3://algorand-staging/releases-page/index.html-previous
aws s3 cp index.html s3://algorand-staging/releases-page/
aws s3 cp index.html s3://algorand-releases/

