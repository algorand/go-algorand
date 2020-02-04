#!/usr/bin/env bash
#
# Create and export the fake keys used by the local test repos.

set -ex

echo
date "+build_release begin TEST stage %Y%m%d_%H%M%S"
echo

echo Setup GPG
"${HOME}"/ben-branch/scripts/release/gpg.sh

"${HOME}"/ben-branch/scripts/release/test/deb/run_ubuntu.sh
date "+build_release done testing ubuntu %Y%m%d_%H%M%S"

"${HOME}"/ben-branch/scripts/release/test/rpm/run_centos.sh
date "+build_release done testing centos %Y%m%d_%H%M%S"

echo
date "+build_release end TEST stage %Y%m%d_%H%M%S"
echo

