#!/bin/sh
# RPM pre-removal script for algorand package

# Systemd pre-uninstall actions (equivalent to %systemd_preun)
if [ $1 -eq 0 ]; then
    # Package removal (not upgrade)
    systemctl --no-reload disable algorand.service >/dev/null 2>&1 || true
    systemctl stop algorand.service >/dev/null 2>&1 || true
    systemctl --no-reload disable 'algorand@*' >/dev/null 2>&1 || true
    systemctl stop 'algorand@*' >/dev/null 2>&1 || true
fi
