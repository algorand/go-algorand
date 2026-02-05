#!/bin/sh
# Debian post-removal script for algorand package

# Mask services on removal
if [ "$1" = "remove" ]; then
    if [ -x "/usr/bin/deb-systemd-helper" ]; then
        deb-systemd-helper mask algorand.service >/dev/null || true
        deb-systemd-helper mask algorand@\* >/dev/null || true
    fi
fi

# Purge services on purge
if [ "$1" = "purge" ]; then
    if [ -x "/usr/bin/deb-systemd-helper" ]; then
        deb-systemd-helper purge algorand.service >/dev/null || true
        deb-systemd-helper unmask algorand.service >/dev/null || true
        deb-systemd-helper purge algorand@\* >/dev/null || true
        deb-systemd-helper unmask algorand@\* >/dev/null || true
    fi
fi

# Reload systemd
if [ -d /run/systemd/system ]; then
    systemctl --system daemon-reload >/dev/null || true
fi
