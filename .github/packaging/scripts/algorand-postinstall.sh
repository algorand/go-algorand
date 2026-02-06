#!/bin/sh
# Post-installation script for algorand package (works for both deb and rpm)

# Detect if we're on a deb or rpm system
if command -v dpkg >/dev/null 2>&1; then
    # Debian/Ubuntu

    # Create algorand system user and group
    # Use useradd/groupadd which are more universally available than adduser
    if ! getent group algorand >/dev/null 2>&1; then
        groupadd --system algorand >/dev/null 2>&1 || true
    fi
    if ! getent passwd algorand >/dev/null 2>&1; then
        useradd --system --gid algorand --home-dir /var/lib/algorand --no-create-home algorand >/dev/null 2>&1 || true
    fi
    chown -R algorand:algorand /var/lib/algorand

    # Systemd service management (only if systemd is running)
    if [ -d /run/systemd/system ]; then
        if [ "$1" = "configure" ] || [ "$1" = "abort-upgrade" ] || [ "$1" = "abort-deconfigure" ] || [ "$1" = "abort-remove" ]; then
            # Unmask service
            deb-systemd-helper unmask algorand.service >/dev/null || true

            if deb-systemd-helper --quiet was-enabled algorand.service; then
                deb-systemd-helper enable algorand.service >/dev/null || true
            else
                deb-systemd-helper update-state algorand.service >/dev/null || true
            fi

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

elif command -v rpm >/dev/null 2>&1; then
    # RHEL/Fedora/CentOS

    # Set ownership of data directory
    chown -R algorand:algorand /var/lib/algorand

    # Systemd post-install actions (only if systemd is running)
    if [ -d /run/systemd/system ]; then
        if [ "$1" -eq 1 ] 2>/dev/null; then
            # Initial installation ($1 is 1 for rpm)
            systemctl preset algorand.service >/dev/null 2>&1 || true
        fi
        systemctl daemon-reload >/dev/null 2>&1 || true
    fi
fi
