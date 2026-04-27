#!/bin/bash

ALPACON_URL=${ALPACON_URL:-"http://host.docker.internal:8000"}
PLUGIN_ID=${PLUGIN_ID:-"756d1a97-a4ec-4d76-a9a0-688f15416abf"}
PLUGIN_KEY=${PLUGIN_KEY:-"alpaca"}

mkdir -p /etc/alpamon /var/lib/alpamon /var/log/alpamon /run/alpamon
chmod 700 /etc/alpamon
chmod 750 /var/lib/alpamon /var/log/alpamon /run/alpamon

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
