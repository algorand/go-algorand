#!/bin/sh
# Debian post-installation script for algorand package

# Create algorand system user and group
adduser --system --group --home /var/lib/algorand --no-create-home algorand >/dev/null 2>&1 || true
# Ensure group exists (adduser above won't create it if user already exists)
getent group algorand >/dev/null || groupadd --system algorand
chown -R algorand:algorand /var/lib/algorand

# Systemd service management
if [ "$1" = "configure" ] || [ "$1" = "abort-upgrade" ] || [ "$1" = "abort-deconfigure" ] || [ "$1" = "abort-remove" ]; then
    # Unmask service
    deb-systemd-helper unmask algorand.service >/dev/null || true

    if deb-systemd-helper --quiet was-enabled algorand.service; then
        deb-systemd-helper enable algorand.service >/dev/null || true
    else
        deb-systemd-helper update-state algorand.service >/dev/null || true
    fi
fi

# Restart or start service
if [ "$1" = "configure" ] || [ "$1" = "abort-upgrade" ] || [ "$1" = "abort-deconfigure" ] || [ "$1" = "abort-remove" ]; then
    if [ -d /run/systemd/system ]; then
        systemctl --system daemon-reload >/dev/null || true
        if [ -n "$2" ]; then
            # Upgrade: restart services
            deb-systemd-invoke restart algorand@\* >/dev/null || true
            deb-systemd-invoke restart algorand.service >/dev/null || true
        else
            # Fresh install: start service
            deb-systemd-invoke start algorand.service >/dev/null || true
        fi
    fi
fi
