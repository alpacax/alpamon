#!/bin/bash
#
# Build all Docker images for testing.
#
# Usage (run from the repo root):
#   ./Dockerfiles/build.sh
#
# Running a container:
#   docker run \
#     --add-host="<your-domain>:host-gateway" \
#     -e ALPACON_URL="http://host.docker.internal:8000" \
#     -e PLUGIN_ID="<your-plugin-id>" \
#     -e PLUGIN_KEY="<your-plugin-key>" \
#     alpamon:<distro>
#
# Notes:
#   --add-host is required so the container can resolve the Alpacon domain
#   to the host machine instead of 127.0.0.1 (which would be the container itself).
#   ALPACON_URL must point to the HTTP API port (default 8000), not the
#   backhaul WebSocket port (8081).

docker build -t alpamon:debian-10 -f Dockerfiles/debian/10/Dockerfile .
docker build -t alpamon:debian-11 -f Dockerfiles/debian/11/Dockerfile .

docker build -t alpamon:ubuntu-18.04 -f Dockerfiles/ubuntu/18.04/Dockerfile .
docker build -t alpamon:ubuntu-20.04 -f Dockerfiles/ubuntu/20.04/Dockerfile .
docker build -t alpamon:ubuntu-22.04 -f Dockerfiles/ubuntu/22.04/Dockerfile .

docker build -t alpamon:redhat-8 -f Dockerfiles/redhat/8/Dockerfile .
docker build -t alpamon:redhat-9 -f Dockerfiles/redhat/9/Dockerfile .

docker build -t alpamon:centos-7 -f Dockerfiles/centos/7/Dockerfile .