#!/usr/bin/env bash

set -ex

echo "[$0] Verifying gpg signatures"

find tmp/node_pkgs -type f -name "*.sig" -exec gpg --verify {} \;

