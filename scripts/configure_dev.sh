#!/usr/bin/env bash
set -e

HELP="Usage: $0 [-s]
Installs host level dependencies necessary to build go-algorand.

Options:
    -s        Skips installing go dependencies
    -f        Force dependencies to be installed (May overwrite existing files)
"

SKIP_GO_DEPS=false
FORCE=false
while getopts ":sfh" opt; do
  case ${opt} in
    s ) SKIP_GO_DEPS=true
      ;;
    f ) FORCE=true
      ;;
    h ) echo "${HELP}"
        exit 0
      ;;
    \? ) echo "${HELP}"
        exit 2
      ;;
  esac
done

SCRIPTPATH="$( cd "$(dirname "$0")" ; pwd -P )"

OS=$("$SCRIPTPATH"/ostype.sh)

function install_or_upgrade {
    if ${FORCE} ; then
        BREW_FORCE="-f"
    fi
    if brew ls --versions "$1" >/dev/null; then
        HOMEBREW_NO_AUTO_UPDATE=1 brew upgrade ${BREW_FORCE} "$1" || true
    else
        HOMEBREW_NO_AUTO_UPDATE=1 brew install ${BREW_FORCE} "$1"
    fi
}

function install_windows_shellcheck() {
    version="v0.7.1"
    wget https://github.com/koalaman/shellcheck/releases/download/$version/shellcheck-$version.zip -O /tmp/shellcheck-$version.zip
    if [ $? -ne 0 ]; then
        rm /tmp/shellcheck-$version.zip &> /dev/null
        echo "Error downloading shellcheck $version"
        return 1
    fi

    unzip -o /tmp/shellcheck-$version.zip shellcheck-$version.exe -d /tmp
    if [ $? -ne 0 ]; then
        rm /tmp/shellcheck-$version.zip &> /dev/null
        echo "Unable to decompress shellcheck $version"
        return 1
    fi

    mv -f /tmp/shellcheck-$version.exe /usr/bin/shellcheck.exe
    if [ $? -ne 0 ]; then
        rm /tmp/shellcheck-$version.zip &> /dev/null
        echo "Unable to move shellcheck to /usr/bin"
        return 1
    fi

    rm /tmp/shellcheck-$version.zip &> /dev/null

    return 0
}

function install_python_packages() {
    pip3 install \
        argparse \
        simplejson \
        awscli
}

if [ "${OS}" = "linux" ]; then
    if ! which sudo > /dev/null
    then
        apt-get update
        apt-get -y install sudo
    fi

    sudo apt-get update
    sudo apt-get install -y libboost-all-dev expect jq autoconf shellcheck sqlite3 python3-venv
elif [ "${OS}" = "darwin" ]; then
    brew update
    brew tap homebrew/cask
    install_or_upgrade pkg-config
    install_or_upgrade boost
    install_or_upgrade jq
    install_or_upgrade libtool
    install_or_upgrade autoconf
    install_or_upgrade automake
    install_or_upgrade shellcheck
    install_or_upgrade python3
elif [ "${OS}" = "windows" ]; then
    pacman -S --disable-download-timeout --noconfirm git automake autoconf m4 libtool make mingw-w64-x86_64-gcc mingw-w64-x86_64-go mingw-w64-x86_64-boost mingw-w64-x86_64-python mingw-w64-x86_64-jq unzip procps
    if [ $? -ne 0 ]
    then
        echo "Error installing pacman dependencies"
        exit 1
    fi

    # Golang probably is not installed under MSYS2 so add the environment variable temporarily
    export GOPATH=$HOME/go

    install_windows_shellcheck
    if [ $? -ne 0 ]
    then
        exit 1
    fi

    # This is required because http://github.com/karalabe/hid library compiles with non-static libraries
    cp /mingw64/bin/libwinpthread-1.dll $GOPATH/bin/ 
fi

install_python_packages

if ${SKIP_GO_DEPS} ; then
    exit 0
fi

"$SCRIPTPATH"/configure_dev-deps.sh
