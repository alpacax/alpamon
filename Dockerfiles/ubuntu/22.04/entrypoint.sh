#!/bin/bash

ALPACON_URL=${ALPACON_URL:-"http://host.docker.internal:8000"}
PLUGIN_ID=${PLUGIN_ID:-"a7282bea-31d7-4b55-a43e-97e1240c90ab"}
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

echo "[entrypoint] creating /var/run/alpamon..."
mkdir -p /var/run/alpamon
chown root:root /var/run/alpamon
chmod 750 /var/run/alpamon

exec /usr/local/alpamon/alpamon