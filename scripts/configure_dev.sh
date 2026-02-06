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
    f)
        FORCE=true
        ;;
    h)
        echo "${HELP}"
        exit 0
        ;;
    \?)
        echo "${HELP}"
        exit 2
        ;;
    esac
done

SCRIPTPATH="$(
    cd "$(dirname "$0")"
    pwd -P
)"

OS=$("$SCRIPTPATH"/ostype.sh)

function install_or_upgrade {
    if ${FORCE}; then
        BREW_FORCE="-f"
    fi
    if brew ls --versions "$1" >/dev/null; then
        HOMEBREW_NO_AUTO_UPDATE=1 brew upgrade ${BREW_FORCE} "$1" || true
    else
        HOMEBREW_NO_AUTO_UPDATE=1 brew install ${BREW_FORCE} "$1"
    fi
}

function install_windows_shellcheck() {
    version="v0.7.1"
    if ! wget https://github.com/koalaman/shellcheck/releases/download/$version/shellcheck-$version.zip -O /tmp/shellcheck-$version.zip; then
        rm /tmp/shellcheck-$version.zip &>/dev/null
        echo "Error downloading shellcheck $version"
        return 1
    fi

    if ! unzip -o /tmp/shellcheck-$version.zip shellcheck-$version.exe -d /tmp; then
        rm /tmp/shellcheck-$version.zip &>/dev/null
        echo "Unable to decompress shellcheck $version"
        return 1
    fi

    if ! mv -f /tmp/shellcheck-$version.exe /usr/bin/shellcheck.exe; then
        rm /tmp/shellcheck-$version.zip &>/dev/null
        echo "Unable to move shellcheck to /usr/bin"
        return 1
    fi

    rm /tmp/shellcheck-$version.zip &>/dev/null

    return 0
}

if [ "${OS}" = "linux" ]; then
    if ! which sudo >/dev/null; then
        DEBIAN_FRONTEND="$DEBIAN_FRONTEND" "$SCRIPTPATH/install_linux_deps.sh"
    else
        sudo "$SCRIPTPATH/install_linux_deps.sh"
    fi
elif [ "${OS}" = "darwin" ]; then
    brew update
    brew_version=$(brew --version | head -1 | cut -d' ' -f2)
    major_version=$(echo $brew_version | cut -d. -f1)
    minor_version=$(echo $brew_version | cut -d. -f2)
    version_decimal="$major_version.$minor_version"
    if (($(echo "$version_decimal < 2.5" | bc -l))); then
        brew tap homebrew/cask
    fi
    install_or_upgrade pkg-config
    install_or_upgrade libtool
    install_or_upgrade shellcheck
    install_or_upgrade jq
    install_or_upgrade autoconf
    install_or_upgrade automake
    install_or_upgrade python3
    install_or_upgrade diffutils
    if [ "$CI" != "true" ] && [ "$CIRCLECI" != "true" ]; then
        install_or_upgrade lnav
        lnav -i "$SCRIPTPATH/algorand_node_log.json"
    fi
elif [ "${OS}" = "windows" ]; then
    if ! $msys2 pacman -S --disable-download-timeout --noconfirm git automake autoconf m4 libtool make mingw-w64-x86_64-gcc mingw-w64-x86_64-python mingw-w64-x86_64-jq unzip procps; then
        echo "Error installing pacman dependencies"
        exit 1
    fi

    if ! install_windows_shellcheck; then
        exit 1
    fi
fi
