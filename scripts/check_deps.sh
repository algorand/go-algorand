#!/usr/bin/env bash

# check_deps.sh - Quickly(!) checks the enlistment for any missing dependencies and attempts to resolve them.
#           Reports if any dependencies are still missing after attempts to resolve.
#
# Syntax:   check_deps.sh
#
# Outputs:  status messages
#
# ExitCode: 0 = All dependencies resolved / present
#
# Usage:    Use before building to ensure dependencies are present (should be nop except after dependencies change)
#
# Examples: scripts/check_deps.sh

GREEN_FG=$(tput setaf 2)
RED_FG=$(tput setaf 1)
TEAL_FG=$(tput setaf 6)
YELLOW_FG=$(tput setaf 3)
END_FG_COLOR=$(tput sgr0)

GOPATH=$(go env GOPATH)
export GOPATH
GOPATH1=$(echo "$GOPATH" | cut -d: -f1)
DEPS=0

installing_dep() {
    echo "$TEAL_FG[INSTALLING]$END_FG_COLOR $1..."
}

check_deps() {
    if [ ! -f "${GOPATH1}/bin/golint" ]
    then
        DEPS=$(( "$DEPS" | 1 ))
    fi

    if [ ! -f "${GOPATH1}/bin/stringer" ]
    then
        DEPS=$(( "$DEPS" | 2 ))
    fi

    if [ ! -f "${GOPATH1}/bin/swagger" ]
    then
        DEPS=$(( "$DEPS" | 4 ))
    fi

    # Don't print `shellcheck`s location.
    if ! which shellcheck > /dev/null
    then
        DEPS=$(( "$DEPS" | 8 ))
    fi
}

check_deps

if [ $DEPS -eq 0 ]
then
    echo "$GREEN_FG[$0]$END_FG_COLOR Required dependencies already installed."
    exit 0
fi

if [ $(( DEPS & 1 )) -ne 0 ]
then
    read -rp "${YELLOW_FG}MISSING DEPENDENCY$END_FG_COLOR \`golint\`. Install? (using go get) (Y/n): " OK
    if [[ "$OK" =~ ^""$|Y|y ]]
    then
        installing_dep golint
        GO111MODULE=off go get -u golang.org/x/lint/golint
        DEPS=$(( "$DEPS" & ~1 ))
    fi
fi

if [ $(( DEPS & 2 )) -ne 0 ]
then
    read -rp "${YELLOW_FG}MISSING DEPENDENCY$END_FG_COLOR \`stringer\`. Install? (using go get) (Y/n): " OK
    if [[ "$OK" =~ ^""$|Y|y ]]
    then
        installing_dep stringer
        GO111MODULE=off go get -u golang.org/x/tools/cmd/stringer
        DEPS=$(( "$DEPS" & ~2 ))
    fi
fi

if [ $(( DEPS & 4 )) -ne 0 ]
then
    read -rp "${YELLOW_FG}MISSING DEPENDENCY$END_FG_COLOR \`swagger\`. Install? (using go get) (Y/n): " OK
    if [[ "$OK" =~ ^""$|Y|y ]]
    then
        installing_dep swagger
        GO111MODULE=off go get -u github.com/go-swagger/go-swagger/cmd/swagger
        DEPS=$(( "$DEPS" & ~4 ))
    fi
fi

if [ $(( DEPS & 8 )) -ne 0 ]
then

    read -rp "${YELLOW_FG}MISSING DEPENDENCY$END_FG_COLOR \`shellcheck\`. Install? (using go get) (Y/n): " OK
    if [[ "$OK" =~ ^""$|Y|y ]]
    then
        OS=$(uname)

        if [ "$OS" == "Linux" ]
        then
            if ! which sudo > /dev/null
            then
                apt-get install sudo -y
            fi

            sudo apt-get install shellcheck -y
        elif [ "$OS" == "Darwin" ]
        then
            brew install shellcheck
        fi

        DEPS=$(( "$DEPS" & ~8 ))
    fi
fi

if [ $DEPS -eq 0 ]
then
    echo -e "$GREEN_FG[$0]$END_FG_COLOR All required dependencies have been installed."
else
    echo -e "$RED_FG[$0]$END_FG_COLOR Required dependencies still missing. Build will probably fail."
    exit 1
fi

