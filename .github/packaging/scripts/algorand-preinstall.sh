#!/usr/bin/env bash
# Pre-installation script for algorand package (works for both deb and rpm)

set -eo pipefail

# Detect package manager
if command -v dpkg &> /dev/null; then
    # Debian/Ubuntu
    if [ "$1" = install ]; then
        if dpkg-query --list 'algorand*' &> /dev/null; then
            if PKG_INFO=$(dpkg-query --show --showformat='${Package} ${Status}\n' 'algorand*' | grep "install ok installed"); then
                # Filter out algorand-indexer and algorand-devtools packages
                INSTALLED_PKG=$(grep -v -e algorand-indexer -e algorand-devtools <<< "$PKG_INFO" | awk '{print $1}')

                if [ -n "$INSTALLED_PKG" ]; then
                    echo -e "\nAlgorand does not currently support multi-distribution installations!\n\
To install this package, first remove the existing package:\n\n\
    sudo apt-get remove $INSTALLED_PKG\n"
                    exit 1
                fi
            fi
        fi
    fi
elif command -v rpm &> /dev/null; then
    # RHEL/Fedora/CentOS
    # Create algorand system group and user if they don't exist
    getent group algorand >/dev/null || \
        groupadd --system algorand >/dev/null
    getent passwd algorand >/dev/null || \
        useradd --system --gid algorand --home-dir /var/lib/algorand --no-create-home algorand >/dev/null
fi
