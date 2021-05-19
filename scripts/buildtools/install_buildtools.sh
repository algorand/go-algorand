#!/usr/bin/env bash
# shellcheck disable=2181

set -exo pipefail

SCRIPTPATH="$( cd "$(dirname "$0")" ; pwd -P )"

(cd ../..; ${SCRIPTPATH}/../check_golang_version.sh dev)

function get_go_version {
    cd "$(dirname "$0")"
    VERSION=$( grep "$1" 2>/dev/null < ./go.mod | awk -F " " '{print $2}')
    echo "$VERSION"
    return
}

function install_go_module {
    local OUTPUT
    local MODULE
    if [[ "$2" != "" ]]; then
        MODULE=$2
    else
        MODULE=$1
    fi
    # Check for version to go.mod version
    VERSION=$(get_go_version "$1")
    if [ -z "$VERSION" ]; then
        OUTPUT=$(GO111MODULE=off go get -u "${MODULE}" 2>&1)
    else
        OUTPUT=$(cd && GO111MODULE=on go get "${MODULE}@${VERSION}" 2>&1)
    fi
    if [ $? != 0 ]; then
        echo "error: executing \"go get ${MODULE}\" failed : ${OUTPUT}"
        exit 1
    fi
}

install_go_module golang.org/x/lint golang.org/x/lint/golint
install_go_module golang.org/x/tools golang.org/x/tools/cmd/stringer
install_go_module github.com/go-swagger/go-swagger github.com/go-swagger/go-swagger/cmd/swagger
install_go_module github.com/algorand/msgp

