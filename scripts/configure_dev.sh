#!/usr/bin/env bash
set -e

SCRIPTPATH="$( cd "$(dirname "$0")" ; pwd -P )"

OS=$(${SCRIPTPATH}/ostype.sh)

function install_or_upgrade {
    if brew ls --versions "$1" >/dev/null; then
        HOMEBREW_NO_AUTO_UPDATE=1 brew upgrade "$1" || true
    else
        HOMEBREW_NO_AUTO_UPDATE=1 brew install "$1"
    fi
}

if [ "${OS}" = "linux" ]; then
    echo "deb [trusted=yes] https://dl.bintray.com/go-swagger/goswagger-debian ubuntu main" | sudo tee /etc/apt/sources.list.d/goswagger.list
    sudo apt-get update
    sudo apt-get -y install libboost-all-dev expect jq swagger
elif [ "${OS}" = "darwin" ]; then
    brew update
    brew tap caskroom/cask
    install_or_upgrade pkg-config
    install_or_upgrade boost
    install_or_upgrade jq
    install_or_upgrade libtool
    install_or_upgrade autoconf
    install_or_upgrade automake
    brew tap go-swagger/go-swagger
    install_or_upgrade go-swagger
fi

${SCRIPTPATH}/configure_dev-deps.sh
