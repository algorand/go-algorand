#!/usr/bin/env bash

# We need to chdir to where the Dockerfile resides so the Docker context is properly set.
# Otherwise, Docker will look for the file to copied in `/var/lib/docker/tmp`, i.e.,
#
#       COPY install.sh .
#

set -e

ALGORAND_DEADLOCK=enable
export ALGORAND_DEADLOCK
BRANCH=$(./scripts/compute_branch.sh)
CHANNEL=$(./scripts/compute_branch_channel.sh "$BRANCH")
BUCKET=${S3_RELEASE_BUCKET:-algorand-builds}

pushd test/packages
./test_release.sh -b "$BUCKET" -c "$CHANNEL"
popd

