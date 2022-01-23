#!/bin/bash

set -eu -o pipefail

API_LEVEL=28
ARCH=arm64
CFLAGS=
ENABLE_CRC=false
ENABLE_CRYPTO=false
NDKDIR=$HOME/android-ndk-r21d

usage() {
	cat << EOF
Usage: $0 [OPTION]... -- [MAKE_TARGET]...
Build libdeflate for Android.

  --api-level=LEVEL    Android API level to target (default: $API_LEVEL)
  --arch=ARCH          Architecture: arm32|arm64 (default: $ARCH)
  --enable-crc         Enable crc instructions
  --enable-crypto      Enable crypto instructions
  --ndkdir=NDKDIR      Android NDK directory (default: $NDKDIR)
EOF
}
if ! options=$(getopt -o '' \
	-l 'api-level:,arch:,enable-crc,enable-crypto,help,ndkdir:' -- "$@"); then
	usage 1>&2
	exit 1
fi

eval set -- "$options"

while [ $# -gt 0 ]; do
	case "$1" in
	--api-level)
		API_LEVEL="$2"
		shift
		;;
	--arch)
		ARCH="$2"
		shift
		;;
	--enable-crc)
		ENABLE_CRC=true
		;;
	--enable-crypto)
		ENABLE_CRYPTO=true
		;;
	--help)
		usage
		exit 0
		;;
	--ndkdir)
		NDKDIR="$2"
		shift
		;;
	--)
		shift
		break
		;;
	*)
		echo 1>&2 "Unknown option \"$1\""
		usage 1>&2
		exit 1
	esac
	shift
done

BINDIR=$NDKDIR/toolchains/llvm/prebuilt/linux-x86_64/bin/

case "$ARCH" in
arm|arm32|aarch32)
	CC=$BINDIR/armv7a-linux-androideabi$API_LEVEL-clang
	if $ENABLE_CRC || $ENABLE_CRYPTO; then
		CFLAGS="-march=armv8-a"
		if $ENABLE_CRC; then
			CFLAGS+=" -mcrc"
		else
			CFLAGS+=" -mnocrc"
		fi
		if $ENABLE_CRYPTO; then
			CFLAGS+=" -mfpu=crypto-neon-fp-armv8"
		else
			CFLAGS+=" -mfpu=neon"
		fi
	fi
	;;
arm64|aarch64)
	CC=$BINDIR/aarch64-linux-android$API_LEVEL-clang
	features=""
	if $ENABLE_CRC; then
		features+="+crc"
	fi
	if $ENABLE_CRYPTO; then
		features+="+crypto"
	fi
	if [ -n "$features" ]; then
		CFLAGS="-march=armv8-a$features"
	fi
	;;
*)
	echo 1>&2 "Unknown architecture: \"$ARCH\""
	usage 1>&2
	exit 1
esac

cmd=(make "-j$(grep -c processor /proc/cpuinfo)" "CC=$CC" "CFLAGS=$CFLAGS" "$@")
echo "${cmd[*]}"
"${cmd[@]}"
