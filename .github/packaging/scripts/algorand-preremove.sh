#!/bin/sh
# Pre-removal script for algorand package (works for both deb and rpm)

if command -v dpkg >/dev/null 2>&1; then
    # Debian/Ubuntu
    # Stop services before removal
    if [ -d /run/systemd/system ] && [ "$1" = remove ]; then
        deb-systemd-invoke stop algorand.service >/dev/null || true
        deb-systemd-invoke stop algorand@\* >/dev/null || true
    fi

elif command -v rpm >/dev/null 2>&1; then
    # RHEL/Fedora/CentOS
    # Systemd pre-uninstall actions (equivalent to %systemd_preun)
    if [ "$1" -eq 0 ] 2>/dev/null; then
        # Package removal (not upgrade) - $1 is 0 for rpm removal
        systemctl --no-reload disable algorand.service >/dev/null 2>&1 || true
        systemctl stop algorand.service >/dev/null 2>&1 || true
        systemctl --no-reload disable 'algorand@*' >/dev/null 2>&1 || true
        systemctl stop 'algorand@*' >/dev/null 2>&1 || true
    fi
fi
