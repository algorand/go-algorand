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

GREEN_FG=$(tput setaf 2 2>/dev/null)
RED_FG=$(tput setaf 1 2>/dev/null)
TEAL_FG=$(tput setaf 6 2>/dev/null)
YELLOW_FG=$(tput setaf 3 2>/dev/null)
END_FG_COLOR=$(tput sgr0 2>/dev/null)

UNAME=$(uname)
if [[ "${UNAME}" == *"MINGW"* ]]; then
	GOPATH=$HOME/go
else
	GOPATH=$(go env GOPATH)
fi
export GOPATH
GO_BIN="$(echo "$GOPATH" | cut -d: -f1)/bin"
MISSING=0

missing_dep() {
    echo "$YELLOW_FG[WARNING]$END_FG_COLOR Missing dependency \`$TEAL_FG${1}$END_FG_COLOR\`."
    MISSING=1
}

GO_DEPS=(
    "$GO_BIN/golint"
    "$GO_BIN/stringer"
    "$GO_BIN/msgp"
)

check_deps() {
    for path in ${GO_DEPS[*]}
    do
        if [ ! -f "$path" ]
        then
            # Parameter expansion is faster than invoking another process.
            # https://www.linuxjournal.com/content/bash-parameter-expansion
            missing_dep "${path##*/}"
        fi
    done

    # Don't print `shellcheck`s location.
    if ! which shellcheck > /dev/null
    then
        missing_dep shellcheck
    fi

    # Don't print `sqlite3`s location.
    if ! which sqlite3 > /dev/null
    then
        missing_dep sqlite3
    fi
}

check_deps

if [ $MISSING -eq 0 ]
then
    echo "$GREEN_FG[$0]$END_FG_COLOR Required dependencies installed."
else
    echo -e "$RED_FG[$0]$END_FG_COLOR Required dependencies missing. Run \`${TEAL_FG}./scripts/configure_dev.sh$END_FG_COLOR\` to install."
    exit 1
fi

