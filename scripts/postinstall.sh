#!/bin/bash

ALPAMON_BIN="/usr/local/bin/alpamon"
TEMPLATE_FILE="/etc/alpamon/alpamon.config.tmpl"

main() {
  check_root_permission
  check_systemd_status
  check_alpamon_binary

  if is_upgrade "$@"; then
    restart_alpamon_by_timer
  else
    # setup_alpamon returns 1 if ENV not set (generic installation)
    # In that case, skip start_systemd_service - user will run 'alpamon register'
    if setup_alpamon; then
      start_systemd_service
    fi
  fi

  cleanup_tmpl_files
}

check_root_permission() {
  if [ "$EUID" -ne 0 ]; then
    echo "Error: Please run the script as root."
    exit 1
  fi
}

check_systemd_status() {
  if ! command -v systemctl &> /dev/null; then
    echo "Error: systemctl is required but could not be found. Please ensure systemd is installed and systemctl is available."
    exit 1
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

  "$ALPAMON_BIN" setup
  if [ $? -ne 0 ]; then
    echo "Error: Alpamon setup command failed."
    exit 1
  fi
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

cleanup_tmpl_files() {
  if [ -f "$TEMPLATE_FILE" ]; then
    echo "Removing template file: $TEMPLATE_FILE"
    rm -f "$TEMPLATE_FILE" || true
  fi
}

# debain
# Initial installation: $1 == configure
# Upgrade: $1 == configure, $2 == old version

# rhel
# Initial installation: $1 == 1
# Upgrade: $1 == 2, and configured to restart on upgrade
is_upgrade() {
    # RHEL
    if [ "$1" -eq 2 ] 2>/dev/null; then
      return 0  # Upgrade
    fi

    # Debian
    if [ "$1" = "configure" ] && [ -n "$2" ]; then
      return 0  # Upgrade
    fi

    return 1 # Initial installation
}

# Exit on error
set -e
main "$@"