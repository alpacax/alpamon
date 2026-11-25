# Exposure report goldens

These files are the goldens of the wire contract for host access-path exposure. The server's tests copy them.

## Wire versions

Alpamon sends `schema_version: 2` in both `POST /api/servers/servers/-/exposure-check/` and `POST /api/servers/servers/-/exposure/`. Version 2 adds `accounts[].key_files[].strict_modes_ok` to each key-file source. It is `true` if the file and its parent directories pass the StrictModes ownership and mode checks, or `false` if any fails. The check includes the canonical home when it is an ancestor of the file and reaches `/` otherwise. The value is `null` when the collector cannot judge the source, such as when the file is absent or the home is unreadable. Both versions carry the separate account-level result at `accounts[].home.strict_modes_ok`.

If either endpoint returns HTTP 400 with an `unsupported_schema_version` error code, Alpamon drops the per-source field, sets `schema_version: 1` and recomputes the hash from the same snapshot. It sends a fresh check with the v1 hash and the original `observed_at`, then sends the v1 report if requested. Alpamon remembers that version for the configured server URL until the process restarts and logs the first fallback at info level. Other HTTP 400 responses end that delivery attempt.

## Layout

- `hosts/<case>/`: a fake Linux host root (`etc/passwd`, `etc/shadow`, `etc/group`, `etc/sudoers*`, `etc/sudo.conf`, `etc/nsswitch.conf`, `etc/ssh/...`, homes, `var/log/wtmp`, `var/log/lastlog`) plus:
  - `sshd-T.txt`: the recorded `sshd -T` output the collector's injected runner returns, or nothing when `case.json` says `"sshd": "missing"`.
  - `case.json`: what git cannot carry: file modes, the owner each path is judged to have, paths the read is denied, the process table for the running sshd, the records `var/log/wtmp` and `var/log/lastlog` are built from, the leak canaries and the paths that must never be opened.
  - `expected.json` and `expected-v2.json`: the v1 and v2 bodies Alpamon sends for that host, sealed with `observed_at` fixed at `2026-11-07T19:30:00Z`.
- `invalid/`: report bodies the server must reject, each the v1 `ubuntu-default` golden with one defect: an unknown reason code, a server-only reason sent by an agent, an `observed_at` in the future and a missing required field. `invalid/oversize.md` describes the body over 2 MiB, which is generated rather than committed.

## Canonical form and hash

The goldens for both versions use canonical JSON followed by one newline. The encoding is UTF-8, object keys sorted, no insignificant whitespace, `null` for an absent value and `[]` for an empty list. Only `"`, `\` and control characters are escaped. `hash` is `sha256:` followed by the hex SHA-256 of that version's canonical JSON with `observed_at` and `hash` removed. The server stores the hash and never recomputes it; the agent's tests recompute it from each golden.

## Regenerating

On Linux, from the repository root:

```bash
EXPOSURE_UPDATE_GOLDEN=1 go test ./pkg/exposure -run 'TestGoldenHosts|TestInvalidFixtures'
```

This rewrites both versions of the report goldens, the accounting binaries from `case.json` and the `invalid/` bodies.
