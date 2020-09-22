#!/usr/bin/env bash
set -e

HELP="Usage: $0 [-s]
Installs host level dependencies necessary to build go-algorand.

Options:
    -s        Skips installing go dependencies
    -f        Force dependencies to be installed (May overwrite existing files)
"

SKIP_GO_DEPS=false
FORCE=false
while getopts ":sfh" opt; do
  case ${opt} in
    s ) SKIP_GO_DEPS=true
      ;;
    f ) FORCE=true
      ;;
    h ) echo "${HELP}"
        exit 0
      ;;
    \? ) echo "${HELP}"
        exit 2
      ;;
  esac
done

SCRIPTPATH="$( cd "$(dirname "$0")" ; pwd -P )"

OS=$("$SCRIPTPATH"/ostype.sh)

function install_or_upgrade {
    if ${FORCE} ; then
        BREW_FORCE="-f"
    fi
    if brew ls --versions "$1" >/dev/null; then
        HOMEBREW_NO_AUTO_UPDATE=1 brew upgrade ${BREW_FORCE} "$1" || true
    else
        HOMEBREW_NO_AUTO_UPDATE=1 brew install ${BREW_FORCE} "$1"
    fi
}

if [ "${OS}" = "linux" ]; then
    if ! which sudo > /dev/null
    then
        apt-get update
        apt-get -y install sudo
    fi

    sudo apt-get update
    sudo apt-get install -y libboost-all-dev expect jq autoconf shellcheck sqlite3 python3-venv
elif [ "${OS}" = "darwin" ]; then
    brew update
    brew tap homebrew/cask
    install_or_upgrade pkg-config
    install_or_upgrade boost
    install_or_upgrade jq
    install_or_upgrade libtool
    install_or_upgrade autoconf
    install_or_upgrade automake
    install_or_upgrade shellcheck
    install_or_upgrade python3
fi

if ${SKIP_GO_DEPS} ; then
    exit 0
fi

"$SCRIPTPATH"/configure_dev-deps.sh

