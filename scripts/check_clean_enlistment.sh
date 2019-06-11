#!/bin/bash

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

# Treat travis builds as 'clean'
if [ -z "${TRAVIS_BRANCH}" ]; then
    if [[ -n $(git status --porcelain) ]]; then
        exit 1
    fi
else
    exit 0
fi
