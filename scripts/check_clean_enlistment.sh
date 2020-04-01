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

# Treat travis and jenkins builds as 'clean'
if [ -z "${TRAVIS_BRANCH}" ] && [ -z "${JENKINS_URL}" ] ; then
  if [[ -n $(git status --porcelain) ]]; then
    exit 1
  fi
fi
exit 0
