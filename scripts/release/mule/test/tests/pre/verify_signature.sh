#!/usr/bin/env bash

set -ex
shopt -s globstar

echo "[$0] Verifying gpg signatures"

find tmp/node_pkgs -type f -name "*.sig" -exec gpg --verify {} \;

