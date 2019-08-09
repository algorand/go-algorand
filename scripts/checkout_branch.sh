#!/bin/bash

# checkout_branch.sh - Safely switches enlistment to the specified remote branch, checked out locally
#           Verifies the enlistment is completely clean to ensure nothing will be clobbered or lost
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

if [ "$#" -ne 1 ]; then
    echo "Syntax: checkout_branch <branch>"
    exit 1
fi

# Anchor our repo root reference location
REPO_ROOT="$( cd "$(dirname "$0")" ; pwd -P )"/..

cd ${REPO_ROOT}

scripts/check_clean_enlistment.sh
if [ $? -ne 0 ]; then
    echo Enlistment has changes. Please clean your enlistment before trying again.
    exit 1
fi

git fetch
if [ $? -ne 0 ]; then
    echo Error fetching repo
    exit 1
fi

git checkout $1
git reset --hard origin/$1
if [ $? -ne 0 ]; then
    echo Error checking out branch "$1"
    exit 1
fi
