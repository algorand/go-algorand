#!/usr/bin/env bash

# keep script execution on errors
set +e

function installGo() {
    OS_ARCH=$1
    GO_VERSION=$("${SCRIPTPATH}/../get_golang_version.sh")
    INSTALLED_GO_VERSION=$("${SCRIPTPATH}/../get_installed_golang_version.sh")
    echo "Ensure Go version ${GO_VERSION} for platform ${OS_ARCH}"
    if [[ "${INSTALLED_GO_VERSION}" != "${GO_VERSION}" ]]; then
        echo "Installing go version ${GO_VERSION} to replace ${INSTALLED_GO_VERSION}"
#        if [[ "${OS_ARCH}" == "linux-arm64" || "${OS_ARCH}" == "linux-armv6l" ]]; then
#            sudo apt -y install ruby-dev libffi-dev make gcc
#            sudo gem install travis
#        fi
        if eval $(gimme "${GO_VERSION}"); then
            go version
        else
            echo "Failed to download go"
            exit 1
        fi
    fi
}

SCRIPTPATH="$( cd "$(dirname "$0")" ; pwd -P )"
OS=$("${SCRIPTPATH}/../ostype.sh")
ARCH=$("${SCRIPTPATH}/../archtype.sh")

if [[ "${OS}" == "linux" ]]; then
    if [[ "${ARCH}" == "arm64" ]]; then
        installGo "linux-arm64"
        set -e
        sudo apt-get update -y
        sudo apt-get -y install sqlite3 python3-venv libffi-dev libssl-dev
    elif [[ "${ARCH}" == "arm" ]]; then
        sudo sh -c 'echo "CONF_SWAPSIZE=1024" > /etc/dphys-swapfile; dphys-swapfile setup; dphys-swapfile swapon'
        installGo "linux-armv6l"
        set -e
        sudo apt-get update -y
        sudo apt-get -y install sqlite3
    elif [[ "${ARCH}" == "amd64" ]]; then
        installGo "linux-amd64"
    fi
elif [[ "${OS}" == "darwin" ]]; then
    installGo "darwin-amd64"
    # we don't want to upgrade boost if we already have it, as it will try to update
    # other components.
    brew update
    brew tap homebrew/cask
    brew pin boost || true
fi

"${SCRIPTPATH}/../configure_dev.sh"
exit $?
