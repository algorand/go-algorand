#!/usr/bin/env bash
set -e

./scripts/check_golang_version.sh dev

HELP="Usage: $0 [-s]
Installs host level dependencies necessary to build go-algorand.

Options:
    -s        Skips installing go dependencies
    -f        Force dependencies to be installed (May overwrite existing files)
"

FORCE=false
while getopts ":sfh" opt; do
  case ${opt} in
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

function install_windows_shellcheck() {
    version="v0.7.1"
    if ! wget https://github.com/koalaman/shellcheck/releases/download/$version/shellcheck-$version.zip -O /tmp/shellcheck-$version.zip; then
        rm /tmp/shellcheck-$version.zip &> /dev/null
        echo "Error downloading shellcheck $version"
        return 1
    fi

    if ! unzip -o /tmp/shellcheck-$version.zip shellcheck-$version.exe -d /tmp; then
        rm /tmp/shellcheck-$version.zip &> /dev/null
        echo "Unable to decompress shellcheck $version"
        return 1
    fi

    if ! mv -f /tmp/shellcheck-$version.exe /usr/bin/shellcheck.exe; then
        rm /tmp/shellcheck-$version.zip &> /dev/null
        echo "Unable to move shellcheck to /usr/bin"
        return 1
    fi

    rm /tmp/shellcheck-$version.zip &> /dev/null

    return 0
}

if [ "${OS}" = "linux" ]; then
    if ! which sudo > /dev/null; then
        "$SCRIPTPATH/install_linux_deps.sh"
    else
        sudo "$SCRIPTPATH/install_linux_deps.sh"
    fi
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
elif [ "${OS}" = "windows" ]; then
    if ! $msys2 pacman -S --disable-download-timeout --noconfirm git automake autoconf m4 libtool make mingw-w64-x86_64-gcc mingw-w64-x86_64-boost mingw-w64-x86_64-python mingw-w64-x86_64-jq unzip procps; then
        echo "Error installing pacman dependencies"
        exit 1
    fi

    if ! install_windows_shellcheck; then
        exit 1
    fi
fi

install_go_module gotest.tools/gotestsum
