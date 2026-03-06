#!/bin/bash

ALPACON_URL=${ALPACON_URL:-"http://host.docker.internal:8081}
PLUGIN_ID=${PLUGIN_ID:-"d59bc536-2f33-43e0-8d78-bca3ecd91b8e"}
PLUGIN_KEY=${PLUGIN_KEY:-"alpaca"}

mkdir -p /etc/alpamon

cat > /etc/alpamon/alpamon.conf <<EOL
[server]
url = $ALPACON_URL
id = $PLUGIN_ID
key = $PLUGIN_KEY

[logging]
debug = true
EOL

echo -e "\nThe following configuration file is being used:\n"
cat /etc/alpamon/alpamon.conf

exec /usr/local/alpamon/alpamon