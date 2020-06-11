#!/usr/bin/env bash

# checkout_branch.sh - Safely switches enlistment to the specified remote branch, checked out locally
#           Verifies the workspace is completely clean to ensure nothing will be clobbered or lost
#
# Syntax:   checkout_branch.sh <branch>
#               -f     Compute full version string (e.g. 1.0.1234)
#
# Outputs:  any errors
#
# ExitCode: 0 = Specified branch checked out successfully
#
# Usage:    Safely switch to the tip of the specified branch
#
# Examples: scripts/checkout_branch.sh master
#           scripts/checkout_branch.sh dev/mybranch

set -eo pipefail

if [ "$#" -ne 1 ]; then
    echo "Syntax: checkout_branch <branch>"
    exit 1
fi

BRANCH="$1"

# Anchor our repo root reference location
export SHELLOPTS
REPO_ROOT="$( cd "$(dirname "$0")" ; pwd -P )"/..

cd "${REPO_ROOT}"

# Check for clean workspace ignoring the update to buildnumber.dat which is expected during a release build.
# Use before a forced checkout to ensure we don't clobber or lose any changes.
if (( $(git status --porcelain | grep -cve "buildnumber\.dat$" ) != 0 )); then
    echo "[WARNING] Your workspace has changes, and this operation will destroy them! Please clean your workspace before trying again."
    exit 1
fi

git fetch
git checkout "$BRANCH"
git reset --hard "origin/$BRANCH"

