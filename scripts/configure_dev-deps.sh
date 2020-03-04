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
install_go_module github.com/algorand/msgp
