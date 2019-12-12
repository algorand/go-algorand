#!/usr/bin/env bash

set -ex

function install_go_module {
    local OUTPUT
    OUTPUT=$(GO111MODULE=off go get -u "$1" 2>&1)
    if [ "${OUTPUT}" != "" ]; then
        echo "error: executing \"go get -u $1\" failed : ${OUTPUT}"
        exit 1
    fi
}

install_go_module golang.org/x/lint/golint
install_go_module golang.org/x/tools/cmd/stringer
install_go_module github.com/go-swagger/go-swagger/cmd/swagger

OS=$(uname)

if [ "$OS" == "Linux" ]
then
    # This script is called from multiple locations, so to be safe we
    # will do this check and not assume it's already been done.
    if ! which sudo > /dev/null
    then
        apt-get update
        apt-get install sudo -y
    fi

    sudo apt-get update
    sudo apt-get install shellcheck -y
elif [ "$OS" == "Darwin" ]
then
    brew install shellcheck
fi

