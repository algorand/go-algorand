#!/usr/bin/env bash

echo
date "+build_release begin SNAPSHOT stage %Y%m%d_%H%M%S"
echo

set -ex

"${HOME}"/go/src/github.com/algorand/go-algorand/scripts/release/prod/deb/snapshot.sh
"${HOME}"/go/src/github.com/algorand/go-algorand/scripts/release/prod/rpm/run_centos.sh

echo
date "+build_release end SNAPSHOT stage %Y%m%d_%H%M%S"
echo

