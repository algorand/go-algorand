#!/usr/bin/env bash
set -e

SCRIPTPATH="$( cd "$(dirname "$0")" ; pwd -P )"

OS=$("$SCRIPTPATH"/ostype.sh)

function install_or_upgrade {
    if brew ls --versions "$1" >/dev/null; then
        HOMEBREW_NO_AUTO_UPDATE=1 brew upgrade "$1" || true
    else
        HOMEBREW_NO_AUTO_UPDATE=1 brew install "$1"
    fi
}

if [ "${OS}" = "linux" ]; then
    if ! which sudo > /dev/null
    then
        apt-get update
        apt-get -y install sudo
    fi

    sudo apt-get update
    sudo apt-get install -y libboost-all-dev expect jq autoconf shellcheck sqlite3
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
fi

"$SCRIPTPATH"/configure_dev-deps.sh

