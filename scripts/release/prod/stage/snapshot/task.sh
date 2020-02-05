#!/usr/bin/env bash

set -ex

echo
date "+build_release begin SNAPSHOT stage %Y%m%d_%H%M%S"
echo

echo Setup GPG
#"${HOME}"/go/src/github.com/algorand/go-algorand/scripts/release/gpg.sh
#"${HOME}"/ben-branch/scripts/release/gpg.sh

#"${HOME}"/go/src/github.com/algorand/go-algorand/scripts/release/prod/deb/snapshot.sh
#"${HOME}"/ben-branch/scripts/release/prod/deb/snapshot.sh
#date "+build_release done snapshotting ubuntu %Y%m%d_%H%M%S"

#"${HOME}"/go/src/github.com/algorand/go-algorand/scripts/release/prod/rpm/run_centos.sh
"${HOME}"/ben-branch/scripts/release/prod/rpm/run_centos.sh
date "+build_release done snapshotting centos %Y%m%d_%H%M%S"

echo
date "+build_release end SNAPSHOT stage %Y%m%d_%H%M%S"
echo

