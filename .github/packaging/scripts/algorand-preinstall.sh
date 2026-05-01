#!/bin/sh
# Pre-installation script for algorand package (works for both deb and rpm)

set -e

# Detect package manager
if command -v dpkg >/dev/null 2>&1; then
    # Debian/Ubuntu
    if [ "$1" = install ]; then
        if dpkg-query --list 'algorand*' >/dev/null 2>&1; then
            PKG_INFO=$(dpkg-query --show --showformat='${Package} ${Status}\n' 'algorand*' | grep "install ok installed" || true)
            if [ -n "$PKG_INFO" ]; then
                # Filter out algorand-indexer and algorand-devtools packages
                INSTALLED_PKG=$(echo "$PKG_INFO" | grep -v -e algorand-indexer -e algorand-devtools | awk '{print $1}' || true)

                if [ -n "$INSTALLED_PKG" ]; then
                    printf '\nAlgorand does not currently support multi-distribution installations!\n'
                    printf 'To install this package, first remove the existing package:\n\n'
                    printf '    sudo apt-get remove %s\n\n' "$INSTALLED_PKG"
                    exit 1
                fi
            fi
        fi
    fi

elif command -v rpm >/dev/null 2>&1; then
    # RHEL/Fedora/CentOS
    # Create algorand system group and user if they don't exist
    getent group algorand >/dev/null || \
        groupadd --system algorand >/dev/null
    getent passwd algorand >/dev/null || \
        useradd --system --gid algorand --home-dir /var/lib/algorand --no-create-home algorand >/dev/null
fi
