#!/bin/sh
# RPM post-installation script for algorand package

# Set ownership of data directory
chown -R algorand:algorand /var/lib/algorand

# Systemd post-install actions (equivalent to %systemd_post)
if [ $1 -eq 1 ]; then
    # Initial installation
    systemctl preset algorand.service >/dev/null 2>&1 || true
fi
systemctl daemon-reload >/dev/null 2>&1 || true
