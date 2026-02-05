#!/bin/sh
# RPM pre-installation script for algorand package

# Create algorand system user if it doesn't exist
getent passwd algorand >/dev/null || \
    useradd --system --home-dir /var/lib/algorand --no-create-home algorand >/dev/null
