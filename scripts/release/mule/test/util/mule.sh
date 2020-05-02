#!/usr/bin/env bash

set -ex

mkdir -p "$WORKDIR/pkg"

mule -f package-test.yaml package-test-setup

