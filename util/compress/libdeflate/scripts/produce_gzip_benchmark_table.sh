#!/bin/bash

set -eu -o pipefail
topdir="$(dirname "$0")/.."

do_benchmark() {
	"$topdir/benchmark" -g -s "$(stat -c %s "$file")" "$@" "$file" \
		| grep Compressed | cut -f 4 -d ' '
}

echo "File | zlib -6 | zlib -9 | libdeflate -6 | libdeflate -9 | libdeflate -12"
echo "-----|---------|---------|---------------|---------------|---------------"

for file in "$@"; do
	echo -n "$(basename "$file")"
	results=()
	results+=("$(do_benchmark -Y -6)")
	results+=("$(do_benchmark -Y -9)")
	results+=("$(do_benchmark -6)")
	results+=("$(do_benchmark -9)")
	results+=("$(do_benchmark -12)")
	best=2000000000
	for result in "${results[@]}"; do
		if (( result < best)); then
			best=$result
		fi
	done
	for result in "${results[@]}"; do
		if (( result == best )); then
			em="**"
		else
			em=""
		fi
		echo -n " | ${em}${result}${em}"
	done
	echo
done
