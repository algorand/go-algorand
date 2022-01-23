#!/bin/sh
#
# Helper script used by run_tests.sh and android_tests.sh,
# not intended to be run directly
#

set -eu

run_cmd() {
	echo "$WRAPPER $*"
	$WRAPPER "$@" > /dev/null
}

for prog in ./test_*; do
	run_cmd "$prog"
done

for format in '' '-g' '-z'; do
	for ref_impl in '' '-Y' '-Z'; do
		run_cmd ./benchmark $format $ref_impl "$TESTDATA"
	done
done
for level in 0 1 3 7 9; do
	for ref_impl in '' '-Y'; do
		run_cmd ./benchmark -$level $ref_impl "$TESTDATA"
	done
done
for level in 0 1 3 7 9 12; do
	for ref_impl in '' '-Z'; do
		run_cmd ./benchmark -$level $ref_impl "$TESTDATA"
	done
done

echo "exec_tests finished successfully" # Needed for 'adb shell'
