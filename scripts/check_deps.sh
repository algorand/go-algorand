#!/usr/bin/env bash

# checkout_deps.sh - Quickly(!) checks the enlistment for any missing dependencies and attempts to resolve them.
#           Reports if any dependencies are still missing after attempts to resolve.
#
# Syntax:   checkout_deps.sh
#
# Outputs:  status messages
#
# ExitCode: 0 = All dependencies resolved / present
#
# Usage:    Use before building to ensure dependencies are present (should be nop except after dependencies change)
#
# Examples: scripts/checkout_deps.sh

export GOPATH=$(go env GOPATH)
GOPATH1=$(echo $GOPATH | cut -d: -f1)

ANY_MISSING=0
# golint doesn't work with 'dep ensure' so we manually install it
GOLINT_MISSING=0
STRINGER_MISSING=0
SWAGGER_MISSING=0

function check_deps() {
    ANY_MISSING=0
    GOLINT_MISSING=0

    if [ ! -f "${GOPATH1}/bin/golint" ]; then
        GOLINT_MISSING=1
        ANY_MISSING=1
        echo "... golint missing"
    fi

    if [ ! -f "${GOPATH1}/bin/stringer" ]; then
        STRINGER_MISSING=1
        ANY_MISSING=1
        echo "... stringer missing"
    fi

    if [ ! -f "${GOPATH1}/bin/swagger" ]; then
        SWAGGER_MISSING=1
        ANY_MISSING=1
        echo "... swagger missing"
    fi

    return ${ANY_MISSING}
}

check_deps
if [ $? -eq 0 ]; then
    echo Required dependencies already installed.
    exit 0
fi

if [ ${GOLINT_MISSING} -ne 0 ]; then
    read -p "Install golint (using go get) (y/N): " OK
    if [ "$OK" = "y" ]; then
        echo "Installing golint..."
        GO111MODULE=off go get -u golang.org/x/lint/golint
    fi
fi

if [ ${STRINGER_MISSING} -ne 0 ]; then
    read -p "Install stringer (using go get) (y/N): " OK
    if [ "$OK" = "y" ]; then
        echo "Installing stringer..."
        GO111MODULE=off go get -u golang.org/x/tools/cmd/stringer
    fi
fi

if [ ${SWAGGER_MISSING} -ne 0 ]; then
    read -p "Install swagger (using go get) (y/N): " OK
    if [ "$OK" = "y" ]; then
        echo "Installing swagger..."
        GO111MODULE=off go get -u github.com/go-swagger/go-swagger/cmd/swagger
    fi
fi

check_deps
if [ $? -eq 0 ]; then
    echo Required dependencies have been installed
    exit 0
else
    echo Required dependencies still missing. Build will probably fail.
    exit 0
fi
