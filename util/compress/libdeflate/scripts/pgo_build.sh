#!/bin/bash

# Try gcc profile-guided optimizations

set -eu

MAKE="make -j$(grep -c processor /proc/cpuinfo)"
DATAFILE="$HOME/data/silesia"

$MAKE benchmark > /dev/null
echo "====================="
echo "Original performance:"
echo "---------------------"
./benchmark "$@" "$DATAFILE"

$MAKE CFLAGS=-fprofile-generate LDFLAGS=-fprofile-generate benchmark > /dev/null
./benchmark "$@" "$DATAFILE" > /dev/null
$MAKE CFLAGS=-fprofile-use benchmark > /dev/null
rm -f {lib,programs}/*.gcda
echo "=========================="
echo "PGO-optimized performance:"
echo "--------------------------"
./benchmark "$@" "$DATAFILE"
