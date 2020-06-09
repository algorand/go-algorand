#!/usr/bin/env bash

set -ex

function install_go_module {
    local OUTPUT
    # Match msgp version to go.mod version
    if [ "$1" = "github.com/algorand/msgp" ]; then
	VERSION=$(cd $(dirname "$0") && cat ../go.mod | grep msgp | awk -F " " '{print $NF}')
	OUTPUT=$(GO111MODULE=on go get "$1@${VERSION}" 2>&1)
    else
	OUTPUT=$(GO111MODULE=off go get -u "$1" 2>&1)
    fi
    if [ "${OUTPUT}" != "" ]; then
        echo "error: executing \"go get -u $1\" failed : ${OUTPUT}"
        exit 1
    fi
}

install_go_module golang.org/x/lint/golint
install_go_module golang.org/x/tools/cmd/stringer
install_go_module github.com/go-swagger/go-swagger/cmd/swagger
install_go_module github.com/algorand/msgp
