#!/usr/bin/env bash

if [ "${dev_env_set}" = "1" ]; then
    echo "Dev Environment already configured"
    return 0
fi

SCRIPTPATH="$( cd "$(dirname "${BASH_SOURCE[0]}" )" ; pwd -P )"

if [ $( ${SCRIPTPATH}/ostype.sh ) = "darwin" ]; then
    export CPLUS_INCLUDE_PATH=/usr/local/include
    export LIBRARY_PATH=/usr/local/lib
fi

export GOROOT=$(go env GOROOT)
export GOPATH="$( cd "${SCRIPTPATH}/../../../../.." ; pwd -P )"
export GOALROOT="${GOPATH}/src/github.com/algorand/go-algorand"

alias s="pushd ${GOALROOT}"
alias ..="cd .."
alias ...="cd ../.."

algodir() {
    export ALGORAND_DATA=${1}
}

export dev_env_set=1

echo "Environment configured for go-algorand development"
