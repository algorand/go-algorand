#!/usr/bin/env bash 

pacman -S --disable-download-timeout --noconfirm git automake autoconf m4 libtool make mingw-w64-x86_64-gcc mingw-w64-x86_64-go mingw-w64-x86_64-boost mingw-w64-x86_64-python mingw-w64-x86_64-jq unzip procps
if [ $? -ne 0 ]
then
	echo "Error installing pacman dependencies"
	exit 1
fi

export GOPATH=$HOME/go

# This is required because http://github.com/karalabe/hid library compiles with non-static libraries
cp /mingw64/bin/libwinpthread-1.dll $GOPATH/bin/

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

$DIR/../configure_dev-deps.sh
if [ $? -ne 0 ]
then
	exit 1
fi

$DIR/install_shellcheck.sh
if [ $? -ne 0 ]
then
	exit 1
fi

