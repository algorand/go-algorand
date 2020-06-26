#!/usr/bin/env bash
#
# Create and export the fake keys used by the local test repos.

set -ex

echo
date "+build_release begin TEST stage %Y%m%d_%H%M%S"
echo

echo Setup GPG
"${HOME}"/go/src/github.com/algorand/go-algorand/scripts/release/test/util/gpg-fake.sh

"${HOME}"/go/src/github.com/algorand/go-algorand/scripts/release/test/deb/run_ubuntu.sh
date "+build_release done testing ubuntu %Y%m%d_%H%M%S"

"${HOME}"/go/src/github.com/algorand/go-algorand/scripts/release/test/rpm/run_centos.sh
date "+build_release done testing centos %Y%m%d_%H%M%S"

echo Use Docker to perform a smoke test.
pushd "${HOME}"/go/src/github.com/algorand/go-algorand/scripts/release/test/util
# Copy all packages to the same directory where the Dockerfile will reside.
cp "${HOME}"/node_pkg/* .
./test_package.sh
popd

echo
date "+build_release end TEST stage %Y%m%d_%H%M%S"
echo

