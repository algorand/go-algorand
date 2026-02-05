#!/usr/bin/env bash
# Debian pre-installation script for algorand package

set -eo pipefail

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
