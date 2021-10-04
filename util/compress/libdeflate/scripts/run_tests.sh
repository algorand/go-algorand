#!/bin/bash
#
# Test script for libdeflate

set -eu -o pipefail
cd "$(dirname "$0")/.."

if [ $# -ne 0 ]; then
	echo 1>&2 "Usage: $0"
	exit 2
fi

# Use CC if specified in environment, else default to "cc".
: "${CC:=cc}"

# Use CFLAGS if specified in environment.
: "${CFLAGS:=}"

CLEANUP_CMDS=()
cleanup() {
	for cmd in "${CLEANUP_CMDS[@]}"; do
		eval "$cmd"
	done
}
trap cleanup EXIT

# Use TESTDATA if specified in environment, else generate it.
if [ -z "${TESTDATA:-}" ]; then
	# Generate default TESTDATA file.
	TESTDATA=$(mktemp -t libdeflate_testdata.XXXXXXXXXX)
	export TESTDATA
	CLEANUP_CMDS+=("rm -f '$TESTDATA'")
	find . '(' -name '*.c' -o -name '*.h' -o -name '*.sh' ')' \
		-exec cat '{}' ';' | head -c 1000000 > "$TESTDATA"
fi

TMPDIR=$(mktemp -d -t libdeflate_test.XXXXXXXXX)
CLEANUP_CMDS+=("rm -r '$TMPDIR'")

MAKE="make -j$(getconf _NPROCESSORS_ONLN)"

CC_VERSION=$($CC --version | head -1)

ARCH=$(uname -m)

for skip in SKIP_FREESTANDING SKIP_VALGRIND SKIP_UBSAN SKIP_ASAN SKIP_CFI \
	    SKIP_SHARED_LIB; do
	if [ "${!skip:-}" = "1" ]; then
		eval $skip=true
	else
		eval $skip=false
	fi
done

###############################################################################

INDENT=0

log() {
	echo -n "[$(date)] "
	head -c $(( INDENT * 4 )) /dev/zero | tr '\0' ' '
	echo "$@"
}

begin() {
	log "$@"
	(( INDENT++ )) || true
}

end() {
	(( INDENT-- )) || true
}

run_cmd() {
	log "$@"
	"$@" > /dev/null
}

fail() {
	echo 1>&2 "$@"
	exit 1
}

file_count() {
	local dir=$1

	find "$dir" -type f -o -type l | wc -l
}

cflags_supported() {
	# -Werror is needed here in order for old versions of clang to reject
	# invalid options.
	echo 'int main(void){ return 0; }' \
		| $CC $CFLAGS "$@" -Werror -x c - -o /dev/null 2>/dev/null
}

valgrind_version_at_least() {
	local want_vers=$1
	local vers

	vers=$(valgrind --version | grep -E -o '[0-9\.]+' | head -1)

	[ "$want_vers" = "$(echo -e "$vers\n$want_vers" | sort -V | head -1)" ]
}

build_and_run_tests() {
	local quick=false
	if [ "${1:-}" = "--quick" ]; then
		quick=true
		shift
	fi

	begin "CC=$CC CFLAGS=\"$CFLAGS\" WRAPPER=\"$WRAPPER\" $*"

	# Build libdeflate, including the test programs.  Set the special test
	# support flag to get support for LIBDEFLATE_DISABLE_CPU_FEATURES.
	$MAKE "$@" TEST_SUPPORT__DO_NOT_USE=1 all test_programs > /dev/null

	# When not using -march=native, run the tests multiple times with
	# different combinations of CPU features disabled.  This is needed to
	# test all variants of dynamically-dispatched code.
	#
	# For now, we aren't super exhausive in which combinations of features
	# we test disabling.  We just disable the features roughly in order from
	# newest to oldest for each architecture, cumulatively.  In practice,
	# that's good enough to cover all the code.
	local features=('')
	if ! [[ "$CFLAGS" =~ "-march=native" ]] && ! $quick; then
		case "$ARCH" in
		i386|x86_64)
			features+=(avx512bw avx2 avx bmi2 pclmul sse2)
			;;
		arm*|aarch*)
			features+=(crc32 pmull neon)
			;;
		esac
	fi
	local disable_str=""
	local feature
	for feature in "${features[@]}"; do
		if [ -n "$feature" ]; then
			if [ -n "$disable_str" ]; then
				disable_str+=","
			fi
			disable_str+="$feature"
		fi
		log "Using LIBDEFLATE_DISABLE_CPU_FEATURES=$disable_str"
		LIBDEFLATE_DISABLE_CPU_FEATURES="$disable_str" \
		    sh ./scripts/exec_tests.sh > /dev/null
	done
	end
}

verify_freestanding_build() {
	# It is expected that sanitizer builds link to external functions.
	if [[ "$CFLAGS" =~ "-fsanitize" ]]; then
		return 0
	fi
	log "Verifying that freestanding build is really freestanding"
	if nm libdeflate.so | grep -q ' U '; then
		echo 1>&2 "Freestanding lib links to external functions!:"
		nm libdeflate.so | grep ' U '
		return 1
	fi
	if ldd libdeflate.so | grep -q -v '\<statically linked\>'; then
		echo 1>&2 "Freestanding lib links to external libraries!:"
		ldd libdeflate.so
		return 1
	fi
}

gzip_tests() {
	local gzips=("$PWD/gzip")
	local gunzips=("$PWD/gunzip")
	if [ "${1:-}" != "--quick" ]; then
		gzips+=(/bin/gzip)
		gunzips+=(/bin/gunzip)
	fi
	local gzip gunzip

	begin "Running gzip program tests with CC=\"$CC\" CFLAGS=\"$CFLAGS\""
	$MAKE gzip gunzip > /dev/null
	for gzip in "${gzips[@]}"; do
		for gunzip in "${gunzips[@]}"; do
			log "GZIP=$gzip, GUNZIP=$gunzip"
			GZIP="$gzip" GUNZIP="$gunzip" TESTDATA="$TESTDATA" \
				./scripts/gzip_tests.sh
		done
	done
	end
}

do_run_tests() {
	build_and_run_tests "$@"
	if [ "${1:-}" != "--quick" ]; then
		if $SKIP_FREESTANDING; then
			log "Skipping freestanding build tests due to SKIP_FREESTANDING=1"
		else
			build_and_run_tests FREESTANDING=1
			verify_freestanding_build
		fi
	fi
	gzip_tests "$@"
}

check_symbol_prefixes() {
	log "Checking that all global symbols are prefixed with \"libdeflate_\""
	$MAKE libdeflate.a > /dev/null
	if nm libdeflate.a | grep ' T ' | grep -E -v " _?libdeflate_"; then
		fail "Some global symbols aren't prefixed with \"libdeflate_\""
	fi
	log "Checking that all exported symbols are prefixed with \"libdeflate\""
	$MAKE libdeflate.so > /dev/null
	if nm libdeflate.so | grep ' T ' \
			| grep -E -v " (libdeflate_|_init\>|_fini\>)"; then
		fail "Some exported symbols aren't prefixed with \"libdeflate_\""
	fi
}

test_use_shared_lib() {
	if $SKIP_SHARED_LIB; then
		log "Skipping USE_SHARED_LIB=1 tests due to SKIP_SHARED_LIB=1"
		return
	fi
	log "Testing USE_SHARED_LIB=1"
	$MAKE gzip > /dev/null
	if ldd gzip | grep -q 'libdeflate.so'; then
		fail "Binary should be statically linked by default"
	fi
	$MAKE USE_SHARED_LIB=1 all check > /dev/null
	ldd gzip > "$TMPDIR/ldd.out"
	if ! grep -q 'libdeflate.so' "$TMPDIR/ldd.out"; then
		cat 1>&2 "$TMPDIR/ldd.out"
		fail "Binary isn't dynamically linked"
	fi
	rm "$TMPDIR/ldd.out"
}

install_uninstall_tests() {
	local shell

	begin "Testing 'make install' and 'make uninstall'"
	for shell in '/bin/bash' '/bin/dash'; do
		log "Trying SHELL=$shell"
		$MAKE SHELL=$shell clean > /dev/null
		$MAKE SHELL=$shell DESTDIR="$TMPDIR/inst" install > /dev/null
		if (( "$(file_count "$TMPDIR/inst")" == 0 )); then
			fail "'make install' didn't install any files"
		fi
		make SHELL=$shell DESTDIR="$TMPDIR/inst" uninstall > /dev/null
		if (( "$(file_count "$TMPDIR/inst")" != 0 )); then
			fail "'make uninstall' didn't uninstall all files"
		fi
		rm -r "$TMPDIR/inst"
	done
	end
}

run_tests() {
	export WRAPPER="" # no wrapper by default; overridden by valgrind tests
	local cflags

	begin "Running tests"
	do_run_tests
	end

	cflags=("-O3")
	if cflags_supported "${cflags[@]}" "-march=native"; then
		cflags+=("-march=native")
	fi
	begin "Running tests with ${cflags[*]}"
	CFLAGS="$CFLAGS ${cflags[*]}" do_run_tests
	end

	# Need valgrind 3.9.0 for '--errors-for-leak-kinds=all'
	# Need valgrind 3.12.0 for armv8 crypto and crc instructions
	if $SKIP_VALGRIND; then
		log "Skipping valgrind tests due to SKIP_VALGRIND=1"
	elif valgrind_version_at_least 3.12.0; then
		begin "Running tests with Valgrind"
		WRAPPER="valgrind --quiet --error-exitcode=100 --leak-check=full --errors-for-leak-kinds=all" \
			do_run_tests --quick
		end
	fi

	cflags=("-fsanitize=undefined" "-fno-sanitize-recover=undefined")
	if $SKIP_UBSAN; then
		log "Skipping UBSAN tests due to SKIP_UBSAN=1"
	elif cflags_supported "${cflags[@]}"; then
		begin "Running tests with UBSAN"
		CFLAGS="$CFLAGS ${cflags[*]}" do_run_tests --quick
		end
	else
		log "Skipping UBSAN tests because compiler ($CC_VERSION) doesn't support UBSAN"
	fi

	cflags=("-fsanitize=address" "-fno-sanitize-recover=address")
	if $SKIP_ASAN; then
		log "Skipping ASAN tests due to SKIP_ASAN=1"
	elif cflags_supported "${cflags[@]}"; then
		begin "Running tests with ASAN"
		CFLAGS="$CFLAGS ${cflags[*]}" do_run_tests --quick
		end
	else
		log "Skipping ASAN tests because compiler ($CC_VERSION) doesn't support ASAN"
	fi

	cflags=("-fsanitize=cfi" "-fno-sanitize-recover=cfi" "-flto"
		"-fvisibility=hidden")
	if $SKIP_CFI; then
		log "Skipping CFI tests due to SKIP_CFI=1"
	elif cflags_supported "${cflags[@]}"; then
		begin "Running tests with CFI"
		CFLAGS="$CFLAGS ${cflags[*]}" AR=llvm-ar do_run_tests --quick
		end
	else
		log "Skipping CFI tests because compiler ($CC_VERSION) doesn't support CFI"
	fi

	install_uninstall_tests
	check_symbol_prefixes
	test_use_shared_lib
}

###############################################################################

log "Starting libdeflate tests"
run_tests
log "All tests passed!"
