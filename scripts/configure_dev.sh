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

function install_windoows_shellcheck() {
    filename="shellcheck-v0.7.0.zip"
    filechecksum="10ee2474845eeb76d8a13992457472b723edf470c7cf182a20b32ecee4ad009ec6b2ca542db8f66127cf19e24baf3a06838a0d101494a5a6c11b3b568f9f5a99"
    wget https://shellcheck.storage.googleapis.com/$filename -O /tmp/$filename
    if [ $? -ne 0 ]
    then
        rm /tmp/$filename &> /dev/null
        echo "Error downloading $filename"
        return 1
    fi

    if [ "$(cat /tmp/$filename | sha512sum | head -c 128)" != "$filechecksum" ]
    then
        rm /tmp/$filename &> /dev/null
        echo "$filename checksum mismatch"
        return 1
    fi

    unzip -o /tmp/shellcheck-v0.7.0.zip shellcheck-v0.7.0.exe -d /tmp
    if [ $? -ne 0 ]
    then
        rm /tmp/$filename &> /dev/null
        echo "Unable to decompress shellcheck file"
        return 1
    fi

    mv -f /tmp/shellcheck-v0.7.0.exe /usr/bin/shellcheck.exe
    if [ $? -ne 0 ]
    then
        rm /tmp/$filename &> /dev/null
        echo "Unable to move shellcheck to /usr/bin"
        exit 1
    fi

    rm /tmp/$filename &> /dev/null

    return 0
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
    pacman -S --disable-download-timeout --noconfirm git automake autoconf m4 libtool mingw-w64-x86_64-python3 make mingw-w64-x86_64-gcc mingw-w64-x86_64-go mingw-w64-x86_64-boost mingw-w64-x86_64-python unzip procps
    if [ $? -ne 0 ]
    then
        echo "Error installing pacman dependencies"
        exit 1
    fi

    export GOPATH=$HOME/go

    install_windoows_shellcheck
    if [ $? -ne 0 ]
    then
        exit 1
    fi
fi

if ${SKIP_GO_DEPS} ; then
    exit 0
fi

"$SCRIPTPATH"/configure_dev-deps.sh

