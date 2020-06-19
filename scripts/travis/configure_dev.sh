#!/usr/bin/env bash

set -x

# keep script execution on errors
set +e

SCRIPTPATH="$( cd "$(dirname "$0")" ; pwd -P )"

OS=$("${SCRIPTPATH}/../ostype.sh")
ARCH=$("${SCRIPTPATH}/../archtype.sh")
GO_VERSION=$(${SCRIPTPATH}/../get_golang_version.sh)

if [ "${OS}" = "linux" ]; then
    if [[ "${ARCH}" = "arm64" ]]; then
        go version 2>/dev/null
        if [ "$?" != "0" ]; then
            echo "Go cannot be found; downloading..."
            # go is not installed ?
	        # e.g. https://dl.google.com/go/go1.13.5.linux-amd64.tar.gz
	        GO_TARBALL=go${GO_VERSION}.linux-amd64.tar.gz
            wget -q https://dl.google.com/go/${GO_TARBALL}
            if [ "$?" = "0" ]; then   
                set -e
                sudo tar -C /usr/local -xzf ${GO_TARBALL}
                rm -f ${GO_TARBALL}
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
	        GO_TARBALL=go${GO_VERSION}.linux-armv6l.tar.gz
            wget -q https://dl.google.com/go/${GO_TARBALL}
            if [ "$?" = "0" ]; then
                set -e
                sudo tar -C /usr/local -xzf ./${GO_TARBALL}
                rm -f ./${GO_TARBALL}
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
