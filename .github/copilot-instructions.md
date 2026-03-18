# Copilot instructions

## Project overview

Alpamon is a Go-based secure server agent for Alpacon. It collects system metrics and executes remote commands, communicating via WebSocket and storing metrics in SQLite (Ent ORM).

## Writing conventions

- **Product names**: Use "Websh" (not "WebSH", "websh", or "WEBSH"). Proper nouns like Alpamon, Alpacon, and Websh should always be capitalized as shown.
- **Sentence case**: Use sentence case for all headings, labels, and documentation (e.g., "Architecture overview" not "Architecture Overview"). Only capitalize the first word and proper nouns.

## Architecture

Commands flow through a handler-based executor pattern:

1. `pkg/runner/` receives WebSocket commands
2. `pkg/executor/dispatcher.go` routes to registered handlers via registry
3. `pkg/executor/handlers/` contains modular handlers: shell, system, file, firewall, terminal, tunnel, user, group, info
4. `pkg/executor/executor.go` runs system commands with privilege demotion and timeout handling

Key packages:
- `pkg/collector/` — System metric collection (realtime and batch)
- `pkg/db/` — Ent ORM with SQLite backend
- `pkg/agent/` — Centralized lifecycle management
- `internal/protocol/` — Command and message protocol definitions
- `internal/pool/` — Worker pool for concurrent tasks

## Code conventions

- Run `go test -v ./... -p 1` for tests (sequential due to SQLite locking)
- Run Ent code generation after schema changes; never edit `pkg/db/ent/` manually
- Platform-specific files use `_darwin.go` / `_linux.go` suffixes
- Timeout exit code is 124 (GNU `timeout` convention)
- Default shell command timeout is 30 minutes
- Firewall operations: backup state before changes, rollback on failure
