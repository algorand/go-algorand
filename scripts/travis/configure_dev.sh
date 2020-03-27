#!/usr/bin/env bash

# keep script execution on errors
set +e

SCRIPTPATH="$( cd "$(dirname "$0")" ; pwd -P )"

OS=$("${SCRIPTPATH}/../ostype.sh")
ARCH=$("${SCRIPTPATH}/../archtype.sh")

if [ "${OS}" = "linux" ]; then
    if [[ "${ARCH}" = "arm64" ]]; then
        go version 2>/dev/null
        if [ "$?" != "0" ]; then
            echo "Go cannot be found; downloading..."
            # go is not installed ?
            wget -q https://dl.google.com/go/go1.13.8.linux-arm64.tar.gz
            if [ "$?" = "0" ]; then   
                set -e
                sudo tar -C /usr/local -xzf ./go1.13.8.linux-arm64.tar.gz
                rm -f ./go1.13.8.linux-arm64.tar.gz
                sudo ln -s /usr/local/go/bin/go /usr/local/bin/go
                sudo ln -s /usr/local/go/bin/godoc /usr/local/bin/godoc
                sudo ln -s /usr/local/go/bin/gofmt /usr/local/bin/gofmt
                go version
            else
                echo "Failed to download go"
                exit 1
            fi
        fi
        set -e
        sudo apt-get update -y
        sudo apt-get -y install sqlite3 python3-venv libffi-dev libssl-dev
    fi
    if [[ "${ARCH}" = "arm" ]]; then
        sudo sh -c 'echo "CONF_SWAPSIZE=1024" > /etc/dphys-swapfile; dphys-swapfile setup; dphys-swapfile swapon'
        go version 2>/dev/null
        if [ "$?" != "0" ]; then
            echo "Go cannot be found; downloading..."
            # go is not installed ?
            wget -q https://dl.google.com/go/go1.12.9.linux-armv6l.tar.gz
            if [ "$?" = "0" ]; then
                set -e
                sudo tar -C /usr/local -xzf ./go1.12.9.linux-armv6l.tar.gz
                rm -f ./go1.12.9.linux-armv6l.tar.gz
                sudo ln -s /usr/local/go/bin/go /usr/local/bin/go
                sudo ln -s /usr/local/go/bin/godoc /usr/local/bin/godoc
                sudo ln -s /usr/local/go/bin/gofmt /usr/local/bin/gofmt
                go version
            else
                echo "Failed to download go"
                exit 1
            fi
        fi
        set -e
        sudo apt-get update -y
        sudo apt-get -y install sqlite3
    fi
elif [ "${OS}" = "darwin" ]; then
    # we don't want to upgrade boost if we already have it, as it will try to update
    # other components.
    brew update
    brew tap homebrew/cask
    brew pin boost || true
fi

"${SCRIPTPATH}/../configure_dev.sh"
exit $?
