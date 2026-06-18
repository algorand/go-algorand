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

function port_install_or_upgrade {
    # MacPorts does not have an exact Homebrew-style install/upgrade UX.
    # We approximate it by upgrading if installed+active, otherwise installing.
    # Caller is expected to have populated the script-level `port_cmd` array.
    local pkg="$1"

    if ${FORCE}; then
        PORT_FORCE="-f"
    fi

    echo "===>  $pkg..."
    if port installed "$pkg" 2>/dev/null | grep -q "(active)"; then
        if ! "${port_cmd[@]}" upgrade ${PORT_FORCE} "$pkg"; then
            return 1
        fi
    else
        if ! "${port_cmd[@]}" install ${PORT_FORCE} "$pkg"; then
            return 1
        fi
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
    # Canonical dep list. Names are resolved per package manager below.
    DARWIN_DEPS=(pkg-config libtool shellcheck jq autoconf automake python3 diffutils)
    DARWIN_DEPS_OPTIONAL=(lnav)

    if which port >/dev/null 2>&1; then
        port_cmd=(port -N)
        if which sudo >/dev/null 2>&1; then
            port_cmd=(sudo port -N)
        fi

        "${port_cmd[@]}" selfupdate

        # Use the latest python3 port available from MacPorts.
        latest_python3_port=$(port search python3 | grep -E '^python3[0-9]{1,2}\s+' | awk '{print $1}' | sort -V | tail -n 1)

        have_python3=false
        if which python3 >/dev/null 2>&1; then
            have_python3=true
        fi

        # MacPorts uses different names for a couple of packages.
        port_name() {
            case "$1" in
                pkg-config) echo pkgconfig ;;
                python3)    echo "$latest_python3_port" ;;
                *)          echo "$1" ;;
            esac
        }

        for pkg in "${DARWIN_DEPS[@]}"; do
            if [ "$pkg" = "python3" ] && $have_python3; then
                echo "Skipping python3 [$(python3 --version)] as already installed"
                echo "Install with 'port install $latest_python3_port && port select --set python3 $latest_python3_port' to use the latest MacPorts version"
                continue
            fi
            port_install_or_upgrade "$(port_name "$pkg")"
        done
        if [ "$CI" != "true" ] ; then
            for pkg in "${DARWIN_DEPS_OPTIONAL[@]}"; do
                port_install_or_upgrade "$(port_name "$pkg")"
            done
            lnav -i "$SCRIPTPATH/algorand_node_log.json"
        fi

        if ! $have_python3; then
            "${port_cmd[@]}" select --set python3 "$latest_python3_port"
        fi

        # all done, no need to fallback to homebrew
        exit 0
    fi

    brew update
    brew_version=$(brew --version | head -1 | cut -d' ' -f2)
    major_version=$(echo $brew_version | cut -d. -f1)
    minor_version=$(echo $brew_version | cut -d. -f2)
    version_decimal="$major_version.$minor_version"
    if (($(echo "$version_decimal < 2.5" | bc -l))); then
        brew tap homebrew/cask
    fi
    for pkg in "${DARWIN_DEPS[@]}"; do
        install_or_upgrade "$pkg"
    done
    if [ "$CI" != "true" ] ; then
        for pkg in "${DARWIN_DEPS_OPTIONAL[@]}"; do
            install_or_upgrade "$pkg"
        done
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
