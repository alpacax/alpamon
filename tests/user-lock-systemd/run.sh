#!/usr/bin/env bash
set -euo pipefail
repo=$(cd "$(dirname "$0")/../.." && pwd)
artifacts=$(mktemp -d)
container="alpamon-user-lock-systemd-$$"
cleanup() {
  docker rm -f "$container" >/dev/null 2>&1 || true
  rm -rf "$artifacts"
}
trap cleanup EXIT
docker build -t alpamon-user-lock-systemd "$repo/tests/user-lock-systemd"
docker run --rm --user 0 -v "$repo:/src:ro" -v "$artifacts:/out" -v "${GOCACHE:?GOCACHE must point to a disposable cache}:/cache" -e GOCACHE=/cache -e CGO_ENABLED=0 -w /src golang:1.26.11 go test -c -tags=integration -o /out/user.test ./pkg/executor/handlers/user
docker run -d --name "$container" --privileged --cgroupns=private --tmpfs /run --tmpfs /run/lock -v "$artifacts:/tests:ro" alpamon-user-lock-systemd >/dev/null
for attempt in $(seq 1 60); do
  if docker exec "$container" systemctl is-system-running --wait >/dev/null 2>&1; then break; fi
  if docker exec "$container" test -d /run/systemd/system; then break; fi
  sleep 1
done
docker exec -e ALPAMON_SYSTEMD_INTEGRATION=1 "$container" /tests/user.test -test.v -test.run '^TestAccountLockSystemdIntegration$' -test.timeout=90s
