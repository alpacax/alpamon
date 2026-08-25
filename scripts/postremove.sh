#!/bin/sh

FILES_TO_REMOVE="
  /etc/alpamon/alpamon.conf
  /usr/lib/tmpfiles.d/alpamon.conf
  /lib/systemd/system/alpamon.service
  /lib/systemd/system/alpamon-restart.service
  /lib/systemd/system/alpamon-restart.timer
  /var/log/alpamon/alpamon.log
  /var/lib/alpamon/alpamon.db
"

# Final removal, spelled differently by each packager:
#   dpkg: "$1" is 'purge'. Plain 'remove' and 'upgrade' keep the config.
#   rpm:  "$1" is the number of instances left, 0 on the final erase and 1 or
#         more on an upgrade. An upgrade must not touch the config, unit,
#         tmpfiles or database.
# Testing for 'purge' alone left every RHEL/SUSE host holding on to
# /etc/alpamon/alpamon.conf -- the agent's API credential -- plus the local
# database and logs after the package was erased, so a later reinstall silently
# re-adopted the credential of a server that had already been removed.
if [ "$1" = 'purge' ] || [ "$1" -eq 0 ] 2>/dev/null; then
    for file in $FILES_TO_REMOVE; do
        rm -f "$file" || true
    done

    if command -v systemctl >/dev/null; then
        systemctl daemon-reload || true
        systemctl reset-failed || true
    fi

    echo "All related configuration, service, and log files have been deleted."
fi