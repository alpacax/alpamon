#!/bin/sh

# Only effective on Debian-based systems where "purge" is supported.
# No effect on RHEL-based systems.

FILES_TO_REMOVE="
  /etc/alpamon/alpamon.conf
  /usr/lib/tmpfiles.d/alpamon.conf
  /lib/systemd/system/alpamon.service
  /lib/systemd/system/alpamon-restart.service
  /lib/systemd/system/alpamon-restart.timer
  /var/log/alpamon/alpamon.log
  /var/lib/alpamon/alpamon.db
"

if [ "$1" = 'purge' ]; then
    for file in $FILES_TO_REMOVE; do
        rm -f "$file" || true
    done

    if command -v systemctl >/dev/null; then
        systemctl daemon-reload || true
        systemctl reset-failed || true
    fi

    echo "All related configuration, service, and log files have been deleted."
fi