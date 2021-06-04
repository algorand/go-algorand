#!/bin/sh

set -e

make -C ../../ clean
make clean
AFL_HARDEN=1 make CC=afl-gcc -C ../../
AFL_HARDEN=1 make CC=afl-gcc

for dir in $(find . -mindepth 1 -maxdepth 1 -type d); do
	rm -rf /tmp/$dir
	cp -va $dir /tmp/$dir
	mkdir -p /tmp/$dir/outputs
done
