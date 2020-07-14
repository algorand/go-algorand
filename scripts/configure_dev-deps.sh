#!/usr/bin/env bash

set -ex

function get_go_version {
    (
	cd $(dirname "$0")
	VERSION=$(cat ../go.mod | grep "$1" 2>/dev/null | awk -F " " '{print $2}')
	echo $VERSION
    )
    return
}

function install_go_module {
    local OUTPUT
    # Check for version to go.mod version
    VERSION=$(get_go_version "$1")
    if [ -z "$VERSION" ]; then
     	OUTPUT=$(GO111MODULE=off go get -u "$1" 2>&1)
    else
     	OUTPUT=$(cd && GO111MODULE=on go get "$1@${VERSION}" 2>&1)
    fi
    if [ $? != 0 ]; then
        echo "error: executing \"go get $1\" failed : ${OUTPUT}"
        exit 1
    fi
}

install_go_module golang.org/x/lint/golint
install_go_module golang.org/x/tools/cmd/stringer
install_go_module github.com/go-swagger/go-swagger/cmd/swagger
install_go_module github.com/algorand/msgp
