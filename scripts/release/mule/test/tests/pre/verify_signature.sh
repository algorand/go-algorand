#!/usr/bin/env bash

set -exo pipefail

echo "[$0] Verifying gpg signatures"

wget -O - https://releases.algorand.com/key.pub | gpg --import
wget -O - https://releases.algorand.com/rpm/rpm_algorand.pub | gpg --import

find tmp/node_pkgs -type f -name "*.sig" -exec gpg --verify {} \;

