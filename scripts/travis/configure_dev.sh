#!/usr/bin/env bash

# keep script execution on errors
set +e
set -x

SCRIPTPATH="$( cd "$(dirname "$0")" ; pwd -P )"

OS=$("${SCRIPTPATH}/../ostype.sh")
ARCH=$("${SCRIPTPATH}/../archtype.sh")
GO_VERSION=$("${SCRIPTPATH}/../get_golang_version.sh")
INSTALLED_GO_VERSION=$("${SCRIPTPATH}/../get_installed_golang_version.sh")
if [ "${OS}" = "linux" ]; then
    if [[ "${ARCH}" = "arm64" ]]; then
        if [ "$INSTALLED_GO_VERSION" != "$GO_VERSION" ]; then
            echo "Correct Go version cannot be found; downloading version $GO_VERSION ..."
            # go is not installed ?
	        # e.g. https://dl.google.com/go/go1.13.5.linux-arm64.tar.gz
	        GO_TARBALL=go${GO_VERSION}.linux-arm64.tar.gz
            wget -q https://dl.google.com/go/${GO_TARBALL}
            if [ "$?" = "0" ]; then   
                set -e
                sudo tar -C /usr/local -xzf ${GO_TARBALL}
                rm -f ${GO_TARBALL}
                sudo ln -sf /usr/local/go/bin/go /usr/local/bin/go
                sudo ln -sf /usr/local/go/bin/godoc /usr/local/bin/godoc
                sudo ln -sf /usr/local/go/bin/gofmt /usr/local/bin/gofmt
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
        if [ "$INSTALLED_GO_VERSION" != "$GO_VERSION" ]; then
            echo "Correct Go version cannot be found; downloading version $GO_VERSION ..."
            # go is not installed ?
	        GO_TARBALL=go${GO_VERSION}.linux-armv6l.tar.gz
            wget -q https://dl.google.com/go/${GO_TARBALL}
            if [ "$?" = "0" ]; then
                set -e
                sudo tar -C /usr/local -xzf ./${GO_TARBALL}
                rm -f ./${GO_TARBALL}
                sudo ln -sf /usr/local/go/bin/go /usr/local/bin/go
                sudo ln -sf /usr/local/go/bin/godoc /usr/local/bin/godoc
                sudo ln -sf /usr/local/go/bin/gofmt /usr/local/bin/gofmt
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
