#!/usr/bin/env bash

set -ex

#mkdir -p "$HOME"/{.gnupg,dummyaptly,dummyrepo,go,gpgbin,keys,pkg,prodrepo}
mkdir -p "$HOME"/{.gnupg,gpgbin,keys}
# This is for the packages.  Put it underneath /projects/go-algorand so all docker images
# have access to it (for instance, in `util/smoke_test.sh`).
mkdir -p "$WORKDIR/pkg"

mule -f package-test.yaml package-test-setup

