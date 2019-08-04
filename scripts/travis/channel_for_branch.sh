#!/usr/bin/env bash

# Compute the channel that will be used by the Makefile when building binaries
CHANNEL=$(./scripts/compute_branch_channel.sh $(./scripts/compute_branch.sh))

# Ideally, we'll look up the parent chain to find master or a rel/* branch.
# For now assume that dev builds are all occurring in the master branch.

echo "${CHANNEL}"
