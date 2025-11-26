#!/bin/sh

# For RPM (0 = remove) and DEB ("remove")
if [ "$1" = "remove" ] || [ "$1" -eq 0 ] 2>/dev/null; then
    echo 'Stopping and disabling Alpamon services...'

    if command -v systemctl >/dev/null; then
        systemctl stop alpamon.service || true
        systemctl disable alpamon.service || true

        systemctl stop alpamon-restart.timer || true
        systemctl disable alpamon-restart.timer || true

        systemctl stop alpamon-restart.service || true
        systemctl disable alpamon-restart.service || true

        systemctl daemon-reload || true
    else
        echo "Systemctl is not available. Skipping service management."
    fi
fi