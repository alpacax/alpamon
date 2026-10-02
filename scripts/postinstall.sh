#!/bin/bash

ALPAMON_BIN="/usr/bin/alpamon"
TEMPLATE_FILE="/etc/alpamon/alpamon.config.tmpl"
SYSTEMD_AVAILABLE=true
ALPAMON_LOG="/var/log/alpamon/alpamon.log"
# Upper bound on how long a deferred restart waits for the agent's upgrade command,
# matching the delay configs/alpamon-restart.timer gives the systemd path.
RESTART_WAIT_LIMIT=300
# A restart drops the agent's in-memory result queue, so the grace must outlast the retries
# Reporter.query in pkg/scheduler/reporter.go gives a failed post of the command's result.
RESTART_GRACE=60
# Holds the token of the newest deferred restart; an older job that finds another token stands down.
RESTART_TOKEN_FILE="/run/alpamon/restart.token"

main() {
  check_root_permission
  check_systemd_status
  check_alpamon_binary

  cleanup_old_binary

  if is_upgrade "$@"; then
    if [ "$SYSTEMD_AVAILABLE" = "true" ]; then
      restart_alpamon_by_timer
    elif agent_command_pid=$(find_agent_command); then
      defer_alpamon_restart "$agent_command_pid"
    else
      restart_alpamon_process
    fi
    # No cleanup_tmpl_files here on purpose. The package re-ships the template
    # on every upgrade and only `alpamon setup` ever consumes it, so deleting it
    # on an upgrade throws away a newly added config key before anything can
    # read it. Leaving it in place keeps the new release's template on disk to
    # diff against the live config.
  else
    # setup_alpamon returns 1 if ENV not set (generic installation)
    # In that case, skip start_systemd_service - user will run 'alpamon register'
    if setup_alpamon; then
      if [ "$SYSTEMD_AVAILABLE" = "true" ]; then
        start_systemd_service
      else
        create_directories
        start_alpamon_process
      fi
      # setup has consumed the template, so it has served its purpose. A generic
      # installation skips setup and keeps it: the operator completes
      # registration afterwards, and `alpamon setup` still needs it then.
      cleanup_tmpl_files
    fi
  fi
}

check_root_permission() {
  if [ "$EUID" -ne 0 ]; then
    echo "Error: Please run the script as root."
    exit 1
  fi
}

check_systemd_status() {
  if ! command -v systemctl &> /dev/null; then
    echo "Notice: systemd is not available. Skipping systemd service setup."
    SYSTEMD_AVAILABLE=false
    return
  fi
  # Require positive confirmation that PID 1 is systemd.
  # Treat missing/unreadable /proc/1/comm as "no systemd" to align with utils.HasSystemd().
  # Use -r (readable) to avoid set -e exit on unreadable files.
  local pid1_comm=""
  if [ -r /proc/1/comm ]; then
    pid1_comm=$(cat /proc/1/comm 2>/dev/null) || true
  fi
  if [ "$pid1_comm" != "systemd" ]; then
    echo "Notice: systemd is not running as init. Skipping service setup."
    SYSTEMD_AVAILABLE=false
    return
  fi
}

# Create required directories matching configs/tmpfile.conf
# and pkg/utils/systemd.go:alpamonDirs. Keep all three in sync.
create_directories() {
  local alpamon_dirs="/etc/alpamon /var/lib/alpamon /var/log/alpamon /run/alpamon"
  # shellcheck disable=SC2086
  mkdir -p $alpamon_dirs
  chmod 0700 /etc/alpamon
  chmod 0750 /var/lib/alpamon /var/log/alpamon /run/alpamon
  # shellcheck disable=SC2086
  if ! chown root:root $alpamon_dirs; then
    echo "Warning: Failed to set ownership to root:root for Alpamon directories: $alpamon_dirs" >&2
  fi
}

check_alpamon_binary() {
  if [ ! -f "$ALPAMON_BIN" ]; then
    echo "Error: Alpamon binary not found at $ALPAMON_BIN"
    exit 1
  fi
}

setup_alpamon() {
  # Skip setup and service start if ENV not set (generic installation)
  # User will run 'alpamon register' which starts the service after registration
  if [ -z "$PLUGIN_ID" ] || [ -z "$PLUGIN_KEY" ]; then
    echo "Notice: Environment variables not set. Skipping automatic setup."
    echo "Please run 'sudo alpamon register' to complete the registration."
    return 1  # Return non-zero to skip start_systemd_service
  fi

  if ! "$ALPAMON_BIN" setup; then
    echo "Error: Alpamon setup command failed."
    exit 1
  fi
}

# Creates the log with the 0640 mode cmd/alpamon/command/register/service_linux.go gives it;
# a redirect that creates it follows the umask.
create_log_file() {
  if [ ! -e "$ALPAMON_LOG" ]; then
    touch "$ALPAMON_LOG"
    chmod 0640 "$ALPAMON_LOG" 2>/dev/null || true
  fi
}

start_alpamon_process() {
  local log_file="$ALPAMON_LOG"
  create_log_file
  echo "Starting Alpamon as a background process..."
  # Trap SIGHUP to prevent the child from being killed when the
  # postinstall script (and its parent shell session) exits.
  # Uses exec to replace the subshell with alpamon directly.
  (trap '' HUP; exec "$ALPAMON_BIN" >>"$log_file" 2>&1) &
  local pid=$!
  sleep 0.5
  if ! kill -0 "$pid" 2>/dev/null; then
    echo "Warning: Alpamon process (PID: $pid) exited immediately. Check $log_file for details." >&2
    return
  fi
  echo "Alpamon started (PID: $pid)."
  echo "Logs: $log_file"
}

restart_alpamon_process() {
  echo "Restarting Alpamon process for upgrade..."
  pkill -x alpamon 2>/dev/null || true
  # Wait for graceful shutdown, then force-kill if still running
  local i=0
  while [ $i -lt 5 ] && pgrep -x alpamon >/dev/null 2>&1; do
    sleep 1
    i=$((i + 1))
  done
  if pgrep -x alpamon >/dev/null 2>&1; then
    echo "Warning: Alpamon did not shut down within 5 seconds, force-killing." >&2
    pkill -9 -x alpamon 2>/dev/null || true
    sleep 1
  fi
  create_directories
  start_alpamon_process
}

# Prints the PID of the ancestor an alpamon process spawned, i.e. the agent's own upgrade command;
# fails when there is none. Reads /proc because minimal container images ship without ps.
find_agent_command() {
  local pid=$$ ppid key value
  while [ "$pid" -gt 1 ]; do
    ppid=""
    while read -r key value; do
      if [ "$key" = "PPid:" ]; then
        ppid=$value
        break
      fi
    done < "/proc/$pid/status" || return 1
    if [ -z "$ppid" ] || [ "$ppid" -lt 1 ]; then
      return 1
    fi
    if [ "$(cat "/proc/$ppid/comm" 2>/dev/null)" = "alpamon" ]; then
      echo "$pid"
      return 0
    fi
    pid=$ppid
  done
  return 1
}

# Restarting at once would kill the agent mid-command and report a truncated failure,
# so the restart waits for the command to exit and the agent to post its result.
defer_alpamon_restart() {
  local command_pid="$1"
  create_directories
  create_log_file
  echo "Alpamon is running this upgrade itself; it will restart after the upgrade command exits."
  # set -m moves the job out of the command's process group, which the agent SIGKILLs on exit;
  # the log redirect keeps it off the output pipe the agent drains.
  local token
  token="$$.$(date +%s%N)"
  echo "$token" > "$RESTART_TOKEN_FILE"
  set -m
  (
    waited=0
    while [ "$waited" -lt "$RESTART_WAIT_LIMIT" ] && kill -0 "$command_pid" 2>/dev/null; do
      sleep 1
      waited=$((waited + 1))
    done
    sleep "$RESTART_GRACE"
    if [ "$(cat "$RESTART_TOKEN_FILE" 2>/dev/null)" != "$token" ]; then
      echo "A later upgrade took over the deferred restart; leaving it to that one."
      exit 0
    fi
    restart_alpamon_process
  ) </dev/null >>"$ALPAMON_LOG" 2>&1 &
  set +m
}

start_systemd_service() {
  echo "Starting systemd service for Alpamon..."

  systemctl daemon-reload || true
  systemctl restart alpamon.service || true
  systemctl enable alpamon.service || true
  systemctl --no-pager status alpamon.service || true

  echo "Alpamon has been installed as a systemd service and will be launched automatically on system boot."
}

restart_alpamon_by_timer() {
  echo "Setting up systemd timer to restart Alpamon..."

  systemctl daemon-reload || true
  systemctl enable alpamon-restart.timer || true
  systemctl reset-failed alpamon-restart.timer || true
  systemctl restart alpamon-restart.timer || true

  echo "Systemd timer to restart Alpamon has been set. It will restart the service in 5 minutes."
}

# Remove the binary left at the install location used before v2.1.1, when the
# packaged binary moved to /usr/bin. /usr/local/bin comes before /usr/bin in the
# default PATH, so a leftover copy there shadows the packaged one and an operator
# keeps running the old agent from the shell. This runs on every install, not
# only on upgrades: gating it on the upgrade path left the stale copy in place
# forever after a remove-then-reinstall.
cleanup_old_binary() {
  if [ -f "/usr/local/bin/alpamon" ] && [ -f "$ALPAMON_BIN" ]; then
    rm -f /usr/local/bin/alpamon
  fi
}

cleanup_tmpl_files() {
  if [ -f "$TEMPLATE_FILE" ]; then
    echo "Removing template file: $TEMPLATE_FILE"
    rm -f "$TEMPLATE_FILE" || true
  fi
}

# The two packagers disagree on how they say "upgrade":
#   dpkg: "$1" is an action verb -- 'configure', or an 'abort-*' verb when a
#         failed upgrade is being rolled back -- and "$2" holds the previously
#         configured version, which is empty only on a fresh install. Keying
#         on "$2" rather than on 'configure' keeps the rollback verbs working.
#   rpm:  "$1" is the number of installed instances after the transaction,
#         1 on a fresh install and 2 or more on an upgrade. A multi-package
#         transaction can leave more than 2, so this is a >= test, not == 2.
#         rpm never passes a second argument, so the dpkg test cannot fire there.
is_upgrade() {
    if [ -n "$2" ]; then
      return 0  # Upgrade (dpkg)
    fi

    if [ "$1" -ge 2 ] 2>/dev/null; then
      return 0  # Upgrade (rpm)
    fi

    return 1 # Initial installation
}

# scripts/postinstall_test.go sets POSTINSTALL_SOURCED and sources this file to drive single functions.
if [ -z "${POSTINSTALL_SOURCED-}" ]; then
  set -e # Exit on error
  main "$@"
fi
