# Exposure report goldens

These files are the goldens of the wire contract between alpamon and the Alpacon server for the host access-path exposure report (`POST /api/servers/servers/-/exposure-check/` and `POST /api/servers/servers/-/exposure/`, `schema_version: 1`). The server's tests copy them. A change here must land together with the matching server change.

## Layout

- `hosts/<case>/`: a fake Linux host root (`etc/passwd`, `etc/shadow`, `etc/group`, `etc/sudoers*`, `etc/sudo.conf`, `etc/nsswitch.conf`, `etc/ssh/...`, homes, `var/log/wtmp`, `var/log/lastlog`) plus:
  - `sshd-T.txt`: the recorded `sshd -T` output the collector's injected runner returns, or nothing when `case.json` says `"sshd": "missing"`.
  - `case.json`: what git cannot carry: file modes, the owner each path is judged to have, paths the read is denied, the process table for the running sshd, the records `var/log/wtmp` and `var/log/lastlog` are built from, the leak canaries and the paths that must never be opened.
  - `expected.json`: the exact body alpamon sends for that host, sealed with `observed_at` fixed at `2026-11-07T19:30:00Z`.
- `invalid/`: report bodies the server must reject, each the `ubuntu-default` golden with one defect: an unknown reason code, a server-only reason sent by an agent, an `observed_at` in the future and a missing required field. `invalid/oversize.md` describes the body over 2 MiB, which is generated rather than committed.

## Canonical form and hash

Each `expected.json` is the canonical JSON of the report followed by one newline: UTF-8, object keys sorted, no insignificant whitespace, `null` for an absent value and `[]` for an empty list. Only `"`, `\` and control characters are escaped. `hash` is `sha256:` followed by the hex SHA-256 of the canonical JSON with `observed_at` and `hash` removed. The server stores the hash and never recomputes it; the agent's tests recompute it from each golden.

## Regenerating

On Linux, from the repository root:

```bash
EXPOSURE_UPDATE_GOLDEN=1 go test ./pkg/exposure -run 'TestGoldenHosts|TestInvalidFixtures'
```

This rewrites `expected.json`, the accounting binaries from `case.json` and the `invalid/` bodies. Review the diff as a contract change.
