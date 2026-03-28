#!/bin/bash

ALPACON_URL=${ALPACON_URL:-"http://host.docker.internal:8000"}
PLUGIN_KEY=${PLUGIN_KEY:-"alpaca"}

if [ -z "$PLUGIN_ID" ]; then
    echo "Error: PLUGIN_ID environment variable is required."
    echo "Usage: docker run -e PLUGIN_ID=<your-plugin-id> [-e ALPACON_URL=...] [-e PLUGIN_KEY=...] <image>"
    exit 1
fi

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
