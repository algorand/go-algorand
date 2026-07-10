#!/bin/sh
# Post-removal script for algorand package (works for both deb and rpm)

if command -v dpkg >/dev/null 2>&1; then
    # Debian/Ubuntu

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

elif command -v rpm >/dev/null 2>&1; then
    # RHEL/Fedora/CentOS
    # Systemd post-uninstall actions (equivalent to %systemd_postun_with_restart)
    systemctl daemon-reload >/dev/null 2>&1 || true

    if [ "$1" -ge 1 ] 2>/dev/null; then
        # Upgrade ($1 >= 1 for rpm upgrade): restart services
        systemctl try-restart algorand.service >/dev/null 2>&1 || true
        systemctl try-restart 'algorand@*' >/dev/null 2>&1 || true
    fi
fi
