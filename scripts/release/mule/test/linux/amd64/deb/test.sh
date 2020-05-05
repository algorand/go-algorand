#!/usr/bin/env bash
# shellcheck disable=1090

set -ex

export WORKDIR="$1"
export OS_TYPE="$2"
export ARCH_TYPE="$3"
export FULLVERSION="$4"

if [ -z "$WORKDIR" ]
then
    echo "WORKDIR must be defined."
    exit 1
fi

. "$WORKDIR/scripts/release/mule/test/util/setup.sh" deb

# The tests executed by `expect` below need a running instance of `goal`.
apt-get update && apt-get install expect "$WORKDIR/tmp/node_pkgs/$OS_TYPE/$ARCH_TYPE"/*.deb -y
expect -d "$WORKDIR/scripts/release/mule/test/$OS_TYPE/$ARCH_TYPE/deb/goal.exp" /var/lib/algorand "$WORKDIR/test/testdata" "$WORKDIR/test/e2e-go/cli/goal/expect"

