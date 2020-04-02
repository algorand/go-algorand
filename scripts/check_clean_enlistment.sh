#!/usr/bin/env bash

# check_clean_enlistment.sh - Checks the git status of the enlistment to see if it's clean.
#
# Syntax:   check_clean_enlistment.sh
#
# Outputs:  none
#
# ExitCode: 0 = Enlistment clean
#
# Usage:    Use before a forced checkout to ensure we don't clobber or lose any changes.
#
# Examples: scripts/check_clean_enlistment.sh

# Check for clean enlistment ignoring the update to buildnumber.dat which is expected during a release build
if [ $(git status --porcelain | grep -v "buildnumber.dat" | wc -l) == 0 ]; then
   exit 0
else
   exit 1
fi
