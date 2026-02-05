#!/bin/sh
# Debian pre-removal script for algorand package

# Stop services before removal
if [ -d /run/systemd/system ] && [ "$1" = remove ]; then
    deb-systemd-invoke stop algorand.service >/dev/null || true
    deb-systemd-invoke stop algorand@\* >/dev/null || true
fi
