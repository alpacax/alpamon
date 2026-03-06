#!/bin/bash

ALPACON_URL=${ALPACON_URL:-"http://host.docker.internal:8081"}
PLUGIN_ID=${PLUGIN_ID:-"97a27261-6029-48b3-89df-b31040a43722"}
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