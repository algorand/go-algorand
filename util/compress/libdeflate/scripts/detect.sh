#!/bin/sh

set -eu

# Use CC if specified in environment, else default to "cc".
: "${CC:=cc}"

# Use CFLAGS if specified in environment.
: "${CFLAGS:=}"

echo "/* THIS FILE WAS AUTOMATICALLY GENERATED.  DO NOT EDIT. */"
echo "#ifndef CONFIG_H"
echo "#define CONFIG_H"

program_compiles() {
	echo "$1" | $CC $CFLAGS -Wno-error -x c - -o /dev/null > /dev/null 2>&1
}

check_function() {
	funcname=$1
	macro="HAVE_$(echo "$funcname" | tr '[:lower:]' '[:upper:]')"

	echo
	echo "/* Is the $funcname() function available? */"
	if program_compiles "int main() { $funcname(); }"; then
		echo "#define $macro 1"
	else
		echo "/* $macro is not set */"
	fi
}

have_stat_field() {
	program_compiles "#include <sys/types.h>
			  #include <sys/stat.h>
			  int main() { struct stat st; st.$1; }"
}

check_stat_nanosecond_precision() {
	echo
	echo "/* Does stat() provide nanosecond-precision timestamps? */"
	if have_stat_field st_atim; then
		echo "#define HAVE_STAT_NANOSECOND_PRECISION 1"
	elif have_stat_field st_atimespec; then
		# Nonstandard field names used by OS X and older BSDs
		echo "#define HAVE_STAT_NANOSECOND_PRECISION 1"
		echo "#define st_atim st_atimespec"
		echo "#define st_mtim st_mtimespec"
		echo "#define st_ctim st_ctimespec"
	else
		echo "/* HAVE_STAT_NANOSECOND_PRECISION is not set */"
	fi
}

check_function clock_gettime
check_function futimens
check_function futimes
check_function posix_fadvise
check_function posix_madvise

check_stat_nanosecond_precision

echo
echo "#endif /* CONFIG_H */"
