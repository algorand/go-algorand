#!/bin/sh
# RPM post-removal script for algorand package

# Systemd post-uninstall actions (equivalent to %systemd_postun_with_restart)
systemctl daemon-reload >/dev/null 2>&1 || true

if [ $1 -ge 1 ]; then
    # Upgrade: restart services
    systemctl try-restart algorand.service >/dev/null 2>&1 || true
    systemctl try-restart 'algorand@*' >/dev/null 2>&1 || true
fi
